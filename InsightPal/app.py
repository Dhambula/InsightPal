import streamlit as st
import pandas as pd
import numpy as np
import cx_Oracle
import pymysql
import psycopg2
import logging
import hashlib
import secrets
import jwt
import openai 
from datetime import datetime, time, timedelta,timezone
from typing import Optional, Dict, Any, List, Tuple
# Add these to the imports section at the top
import json
import re
from urllib.parse import quote_plus
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama.llms import OllamaLLM
# Authentication Imports
import streamlit_authenticator as stauth

# Other Imports
from pandasai import SmartDataframe
from pandasai.llm import OpenAI

from hash import OllamaService, SQLGenerationService

# --- Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Security Configuration ---
SESSION_TIMEOUT = 1800  # 30 minutes
MAX_QUERY_ROWS = 1000
ALLOWED_FILE_TYPES = ["csv", "xlsx", "parquet"]
JWT_SECRET = st.secrets["security"]["jwt_secret"]  # Store in secrets.toml
JWT_EXPIRY = 86400  # 24 hours in seconds

# --- Database Drivers ---
SUPPORTED_DBS = {
    "Oracle": {"port": 1521, "driver": cx_Oracle},
    "MySQL": {"port": 3306, "driver": pymysql},
    "PostgreSQL": {"port": 5432, "driver": psycopg2},
}

# --- Authentication Database Connection ---
def get_auth_db_connection():
    try:
        conn = pymysql.connect(
            host=st.secrets["mysql"]["host"],
            user=st.secrets["mysql"]["user"],
            password=st.secrets["mysql"]["password"],
            database=st.secrets["mysql"]["database"],
            cursorclass=pymysql.cursors.DictCursor,
        )
        return conn
    except Exception as e:
        logger.error(f"Authentication database connection failed: {str(e)}")
        st.error("Failed to connect to authentication database")
        return None

# --- Password Utilities ---
def hash_password(password: str) -> str:
    """Generate a secure hash of the password"""
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pw_hash}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored password against the provided password"""
    if not stored_password or "$" not in stored_password:
        return False
    salt, pw_hash = stored_password.split("$", 1)
    computed_hash = hashlib.sha256((provided_password + salt).encode()).hexdigest()
    return secrets.compare_digest(pw_hash, computed_hash)

# --- JWT Token Management ---
def create_token(user_id: int, username: str, roles: List[str]) -> str:
    """Create a JWT token for the user"""
    payload = {
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRY),
        "iat": datetime.utcnow(),
        "sub": user_id,
        "username": username,
        "roles": roles,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def validate_token(token: str) -> Optional[Dict]:
    """Validate a JWT token and return payload if valid"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --- Authentication Manager ---
class MySQLAuthManager:
    def __init__(self):
        self.conn = get_auth_db_connection()

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """Authenticate a user and return user details if successful"""
        if not self.conn:
            return False, None
        try:
            with self.conn.cursor() as cursor:
                # Get user details
                cursor.execute(
                    "SELECT u.user_id, u.username, u.password_hash, u.email, u.full_name, "
                    "GROUP_CONCAT(r.role_name) as roles "
                    "FROM users u "
                    "LEFT JOIN user_roles ur ON u.user_id = ur.user_id "
                    "LEFT JOIN roles r ON ur.role_id = r.role_id "
                    "WHERE u.username = %s AND u.is_active = TRUE "
                    "GROUP BY u.user_id",
                    (username,),
                )
                user = cursor.fetchone()
                if not user:
                    return False, None
                # Verify password
                if not verify_password(user["password_hash"], password):
                    return False, None
                # Update last login time
                cursor.execute(
                    "UPDATE users SET last_login = NOW() WHERE user_id = %s", (user["user_id"],)
                )
                self.conn.commit()
                # Log login activity
                cursor.execute(
                    "INSERT INTO activity_logs (user_id, action_type, ip_address) VALUES (%s, %s, %s)",
                    (user["user_id"], "login", st.session_state.get("client_ip", "unknown")),
                )
                self.conn.commit()
                # Format user details
                user_data = {
                    "id": user["user_id"],
                    "username": user["username"],
                    "email": user["email"],
                    "name": user["full_name"],
                    "roles": user["roles"].split(",") if user["roles"] else [],
                }
                return True, user_data
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False, None

    def register_user(self, username: str, email: str, full_name: str, password: str,
                  pre_authorized_emails: List[str] = None) -> bool:
        """Register a new user"""
        if not self.conn:
            return False
    
        # Check if pre-authorization is required and if the email is pre-authorized
        if pre_authorized_emails and email not in pre_authorized_emails:
            st.error("This email is not pre-authorized for registration")
            return False
    
        try:
            with self.conn.cursor() as cursor:
                # Check if username or email already exists
                cursor.execute(
                    "SELECT COUNT(*) as count FROM users WHERE username = %s OR email = %s",
                    (username, email)
                )
                result = cursor.fetchone()
                if result['count'] > 0:
                    st.error("Username or email already exists")
                    return False
            
                # Create the user
                cursor.execute(
                    "INSERT INTO users (username, password_hash, email, full_name) VALUES (%s, %s, %s, %s)",
                    (username, hash_password(password), email, full_name)
                )
            
                # Get the new user's ID
                cursor.execute("SELECT LAST_INSERT_ID() as user_id")
                user_id = cursor.fetchone()['user_id']
            
                # Assign roles based on predefined emails
                if pre_authorized_emails and email in pre_authorized_emails:
                    # Assign 'admin' or 'editor' role for predefined emails
                    roles_to_assign = ['admin']  # Change this to ['editor'] if needed
                else:
                    # Default role for other users
                    roles_to_assign = ['viewer']
            
                # Assign roles
                for role in roles_to_assign:
                    cursor.execute(
                        "INSERT INTO user_roles (user_id, role_id) "
                        "SELECT %s, role_id FROM roles WHERE role_name = %s",
                        (user_id, role)
                    )
            
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            self.conn.rollback()
            return False
    
    def reset_password(self, user_id: int, new_password: str) -> bool:
        """Reset a user's password"""
        if not self.conn:
            return False
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE user_id = %s",
                    (hash_password(new_password), user_id),
                )
                self.conn.commit()
                # Log password reset with IP address
                cursor.execute(
                    "INSERT INTO activity_logs (user_id, action_type, ip_address) VALUES (%s, %s, %s)",
                    (
                        user_id, 
                        "password_reset", 
                        st.session_state.get("client_ip", "unknown")
                    ),
                )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            self.conn.rollback()
            return False
    
    def get_user_permissions(self, user_id: int) -> Dict[str, Dict[str, bool]]:
        """Get all data source permissions for a user based on their roles"""
        if not self.conn:
            return {}
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT ds.source_id, ds.source_name, ds.source_type, "
                    "MAX(rp.can_read) as can_read, "
                    "MAX(rp.can_write) as can_write, "
                    "MAX(rp.can_execute) as can_execute "
                    "FROM users u "
                    "JOIN user_roles ur ON u.user_id = ur.user_id "
                    "JOIN role_permissions rp ON ur.role_id = rp.role_id "
                    "JOIN data_sources ds ON rp.source_id = ds.source_id "
                    "WHERE u.user_id = %s "
                    "GROUP BY ds.source_id, ds.source_name, ds.source_type",
                    (user_id,),
                )
                permissions = {}
                for row in cursor.fetchall():
                    permissions[row["source_name"]] = {
                        "type": row["source_type"],
                        "read": bool(row["can_read"]),
                        "write": bool(row["can_write"]),
                        "execute": bool(row["can_execute"]),
                    }
                return permissions
        except Exception as e:
            logger.error(f"Error fetching permissions: {str(e)}")
            return {}

    def log_activity(
        self,
        user_id: int,
        action_type: str,
        action_details: str = None,
        source_id: int = None,
    ) -> bool:
        """Log user activity"""
        if not self.conn:
            return False
        try:
            with self.conn.cursor() as cursor:
                # Ensure we have all required fields
                ip_address = st.session_state.get("client_ip", "unknown")
            
                cursor.execute(
                    "INSERT INTO activity_logs (user_id, action_type, action_details, source_id, ip_address) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        user_id,
                        action_type,
                        action_details,
                        source_id,
                        ip_address,
                    ),
                )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Activity logging error: {str(e)}")
            return False
    
    def get_pre_authorized_emails(self) -> List[str]:
        """Get list of pre-authorized emails for registration"""
        if not self.conn:
            return []
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT email FROM pre_authorized_emails")
                emails = [row["email"] for row in cursor.fetchall()]
                return emails
        except Exception as e:
            logger.error(f"Error fetching pre-authorized emails: {str(e)}")
            return []

    def user_exists(self, username_or_email: str) -> Optional[Dict]:
        """Check if a user exists by username or email"""
        if not self.conn:
            return None
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT user_id, username, email, full_name FROM users "
                    "WHERE username = %s OR email = %s",
                    (username_or_email, username_or_email),
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"User lookup error: {str(e)}")
            return None

    def create_password_reset_token(self, user_id: int) -> Optional[str]:
        """Create a password reset token"""
        if not self.conn:
            return None
        try:
            # Generate token
            token = secrets.token_urlsafe(32)
            expiry = datetime.utcnow() + timedelta(hours=24)
            with self.conn.cursor() as cursor:
                # Remove any existing tokens for this user
                cursor.execute(
                    "DELETE FROM password_reset_tokens WHERE user_id = %s", (user_id,)
                )
                # Create new token
                cursor.execute(
                    "INSERT INTO password_reset_tokens (user_id, token, expiry) "
                    "VALUES (%s, %s, %s)",
                    (user_id, token, expiry),
                )
                self.conn.commit()
                return token
        except Exception as e:
            logger.error(f"Error creating reset token: {str(e)}")
            self.conn.rollback()
            return None

    def verify_reset_token(self, token: str) -> Optional[int]:
        """Verify a password reset token and return the user ID if valid"""
        if not self.conn:
            return None
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT user_id FROM password_reset_tokens "
                    "WHERE token = %s AND expiry > NOW()",
                    (token,),
                )
                result = cursor.fetchone()
                return result["user_id"] if result else None
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return None

    def get_all_users(self) -> List[Dict]:
        """Get all users (admin function)"""
        if not self.conn:
            return []
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT u.user_id, u.username, u.email, u.full_name, u.is_active, "
                    "u.created_at, u.last_login, GROUP_CONCAT(r.role_name) as roles "
                    "FROM users u "
                    "LEFT JOIN user_roles ur ON u.user_id = ur.user_id "
                    "LEFT JOIN roles r ON ur.role_id = r.role_id "
                    "GROUP BY u.user_id "
                    "ORDER BY u.created_at DESC"
                )
                users = []
                for row in cursor.fetchall():
                    users.append(
                        {
                            "id": row["user_id"],
                            "username": row["username"],
                            "email": row["email"],
                            "name": row["full_name"],
                            "active": bool(row["is_active"]),
                            "created": row["created_at"],
                            "last_login": row["last_login"],
                            "roles": row["roles"].split(",") if row["roles"] else [],
                        }
                    )
                return users
        except Exception as e:
            logger.error(f"Error fetching users: {str(e)}")
            return []

    def update_user_roles(self, user_id: int, roles: List[str]) -> bool:
        """Update a user's roles"""
        if not self.conn:
            return False
        try:
            with self.conn.cursor() as cursor:
                # Remove existing roles
                cursor.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                # Add new roles
                for role in roles:
                    cursor.execute(
                        "INSERT INTO user_roles (user_id, role_id) "
                        "SELECT %s, role_id FROM roles WHERE role_name = %s",
                        (user_id, role),
                    )
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Role update error: {str(e)}")
            self.conn.rollback()
            return False

    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

# --- Database Connection Pool ---
class ConnectionManager:
    _connections = {}
    
    @classmethod
    def get_connection(cls, db_type: str, config: Dict[str, Any]):
        key = hash(frozenset(config.items()))
        if key not in cls._connections:
            driver = SUPPORTED_DBS[db_type]["driver"]
            try:
                if db_type == "Oracle":
                    dsn = driver.makedsn(
                        config["host"],
                        config["port"],
                        service_name=config["service_name"],
                    )
                    conn = driver.connect(
                        user=config["user"], 
                        password=config["password"], 
                        dsn=dsn
                    )
                else:
                    conn = driver.connect(
                        host=config["host"],
                        port=config["port"],
                        user=config["user"],
                        password=config["password"],
                        database=config.get("database"),
                    )
                cls._connections[key] = conn
            except Exception as e:
                logger.error(f"Connection failed: {str(e)}")
                raise
        return cls._connections[key]

 
    def extract_schema(conn, db_type: str) -> str:
        """Extract database schema information
    
        Args:
            conn: Either a SQLAlchemy Engine/Connection or a raw DB-API connection
            db_type: Type of database (mysql, postgresql, etc.)
    
        Returns:
            JSON string containing the database schema
        """
        schema = {}
        db_type = db_type.lower()
    
        try:
            # Handle SQLAlchemy connection
            if hasattr(conn, 'execute') and hasattr(conn, 'engine'):
                inspector = inspect(conn)
            
                # Get tables
                try:
                    tables = inspector.get_table_names()
                except Exception as e:
                    logger.error(f"Error getting tables via inspector: {e}")
                    tables = []
                
                    # MySQL fallback
                    if db_type == 'mysql':
                        result = conn.execute(text("SHOW TABLES"))
                        tables = [row[0] for row in result]
            
                # Process tables
                for table in tables:
                    try:
                        # Get columns
                        columns = inspector.get_columns(table)
                        column_info = [{
                            "name": col['name'],
                            "type": str(col['type']),
                            "nullable": col.get('nullable', False),
                            "primary_key": col.get('primary_key', False)
                        } for col in columns]
                    
                        schema[table] = column_info
                    
                        # Get primary keys
                        if any(col['primary_key'] for col in columns):
                            schema[f"{table}_primary_keys"] = [
                                col['name'] for col in columns if col['primary_key']
                            ]
                    
                        # Get foreign keys
                        try:
                            foreign_keys = inspector.get_foreign_keys(table)
                            if foreign_keys:
                                schema[f"{table}_foreign_keys"] = foreign_keys
                        except Exception as e:
                            logger.error(f"Error getting foreign keys for {table}: {e}")
                            schema[f"{table}_foreign_keys"] = {"error": str(e)}
                        
                    except Exception as e:
                        logger.error(f"Error processing table {table}: {e}")
                        schema[table] = {"error": str(e)}
        
            # Handle raw PyMySQL connection
            elif db_type == 'mysql' and hasattr(conn, 'cursor'):
                try:
                    cursor = conn.cursor()
                
                    # Get tables
                    cursor.execute("SHOW TABLES")
                    tables = [row[0] for row in cursor.fetchall()]
                
                    # Process tables
                    for table in tables:
                        try:
                            # Get columns
                            cursor.execute(f"SHOW COLUMNS FROM `{table}`")  # Use backticks for table names
                            columns = cursor.fetchall()
                            column_info = []
                            primary_keys = []
                        
                            for col in columns:
                                column_info.append({
                                    "name": col[0],
                                    "type": col[1],
                                    "nullable": col[2] == "YES",
                                    "primary_key": col[3] == "PRI"
                                })
                                if col[3] == "PRI":
                                    primary_keys.append(col[0])
                        
                            schema[table] = column_info
                        
                            # Add primary keys if found
                            if primary_keys:
                                schema[f"{table}_primary_keys"] = primary_keys
                        
                            # Get foreign keys
                            try:
                                cursor.execute(f"""
                                    SELECT 
                                        COLUMN_NAME, 
                                        REFERENCED_TABLE_NAME, 
                                        REFERENCED_COLUMN_NAME,
                                        CONSTRAINT_NAME
                                    FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                                    WHERE 
                                        TABLE_SCHEMA = DATABASE() AND
                                        TABLE_NAME = '{table}' AND 
                                        REFERENCED_TABLE_NAME IS NOT NULL
                                    GROUP BY CONSTRAINT_NAME, COLUMN_NAME
                                """)
                                foreign_keys = cursor.fetchall()
                            
                                if foreign_keys:
                                    # Group by constraint name to handle composite keys
                                    fk_dict = {}
                                    for fk in foreign_keys:
                                        if fk[3] not in fk_dict:
                                            fk_dict[fk[3]] = {
                                                "constrained_columns": [fk[0]],
                                                "referred_table": fk[1],
                                                "referred_columns": [fk[2]]
                                            }
                                        else:
                                            fk_dict[fk[3]]["constrained_columns"].append(fk[0])
                                            fk_dict[fk[3]]["referred_columns"].append(fk[2])
                                
                                    schema[f"{table}_foreign_keys"] = list(fk_dict.values())
                                
                            except Exception as e:
                                logger.error(f"Error getting foreign keys for {table}: {e}")
                                schema[f"{table}_foreign_keys"] = {"error": str(e)}
                            
                        except Exception as e:
                            logger.error(f"Error processing table {table}: {e}")
                            schema[table] = {"error": str(e)}
                
                except Exception as e:
                    logger.error(f"Database error: {e}")
                    return json.dumps({"error": str(e)}, indent=2)
                finally:
                    try:
                        cursor.close()
                    except:
                        pass
        
            else:
                raise ValueError(f"Unsupported connection type for {db_type}")
            
        except Exception as e:
            logger.error(f"Schema extraction failed: {e}")
            return json.dumps({"error": str(e)}, indent=2)
    
        return json.dumps(schema, indent=2)
    
from google.generativeai import configure, GenerativeModel

from google.generativeai import configure, GenerativeModel
import google.api_core.exceptions

from google.generativeai import configure, GenerativeModel
import google.generativeai as genai

class AIService:
    def __init__(self, model_type: str = "pandasai"):
        self.model_type = model_type
        self._model = None  # Main analysis model
        self._sql_services = None  # Will be initialized lazily
        self._initialize_model()
        
    def _initialize_model(self):
        """Initialize the selected AI model"""
        try:
            if self.model_type == "pandasai":
                self._model = PandasAIService()
            elif self.model_type in self.sql_services:
                self._model = self.sql_services[self.model_type]
            else:
                raise ValueError(f"Unknown model type: {self.model_type}")
        except Exception as e:
            st.error(f"Failed to initialize {self.model_type} model: {str(e)}")
            logger.error(f"Model initialization error: {str(e)}")
            # Fallback to ChatGPT if available
            if "chatgpt" in self.sql_services:
                self._model = self.sql_services["chatgpt"]
    
    @property
    def sql_services(self):
        """Lazy initialization of SQL services"""
        if self._sql_services is None:
            self._sql_services = {
                "chatgpt": ChatGPTService(),
                "ollama": OllamaService()
            }
            
            # Only add Gemini if API key is available
            if "gemini" in st.secrets and st.secrets["gemini"].get("api_key"):
                try:
                    self._sql_services["gemini"] = GeminiService()
                except Exception as e:
                    logger.warning(f"Could not initialize Gemini: {str(e)}")
                    st.warning("Gemini model not available")
                    
        return self._sql_services
    
    def analyze_data(self, df: pd.DataFrame, question: str) -> str:
        """Analyze data using the selected model"""
        if not self._model:
            return "Model not initialized"
        return self._model.analyze_data(df, question)
    
    def generate_sql(self, nl_query: str, schema_info: str = "") -> str:
        """Generate SQL from natural language"""
        if not nl_query:
            return "No query provided"
            
        # Get the appropriate SQL service based on UI selection
        selected_service = st.session_state.get("selected_sql_service", "chatgpt")
        
        if selected_service not in self.sql_services:
            return "Selected SQL service not available"
            
        try:
            return self.sql_services[selected_service].generate_sql(nl_query, schema_info)
        except Exception as e:
            logger.error(f"SQL generation failed: {str(e)}")
            return f"SQL generation error: {str(e)}"
        
class PandasAIService:
    def __init__(self):
        self.llm = OpenAI(api_token=st.secrets["pandasai"]["api_key"])
        self.smart_df = None

    def analyze_data(self, df: pd.DataFrame, question: str) -> str:
        try:
            self.smart_df = SmartDataframe(
                df,
                config={
                    "llm": self.llm,
                    "enable_cache": False,
                    "verbose": True,
                },
            )
            response = self.smart_df.chat(question)
            return str(response)
        except Exception as e:
            logger.error(f"PandasAI analysis failed: {str(e)}")
            return f"Analysis error: {str(e)}"

class ChatGPTService(SQLGenerationService):
    def __init__(self):
        """Initialize with proper error handling"""
        try:
            self.client = openai.OpenAI(api_key=st.secrets["openai"]["api_key"])
            self.model_name = "gpt-4"
        except Exception as e:
            logger.error(f"ChatGPT init failed: {str(e)}")
            raise ConnectionError(f"ChatGPT initialization failed: {str(e)}")
    
    def generate_sql(self, nl_query: str, schema_info: str = "") -> str:
        """Generate SQL with proper cleaning"""
        try:
            prompt = f"""Convert this natural language to SQL:
            Schema: {schema_info}
            Request: {nl_query}
            Return ONLY the SQL query without any explanations or markdown formatting.
            SQL Query:"""
            
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a SQL expert"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            return self._clean_sql(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"ChatGPT SQL generation failed: {str(e)}")
            return f"ChatGPT error: {str(e)}"
    
    def _clean_sql(self, sql: str) -> str:
        """Clean SQL output"""
        cleaned = re.sub(r"```sql|```", "", sql)
        return cleaned.strip().strip('"').strip("'")

class GeminiService(SQLGenerationService):
    def __init__(self):
        """Initialize with proper error handling and rate limiting"""
        self._initialized = False
        self._disabled = False
        self._last_request_time = None
        self._rate_limit_reset = None
        
        try:
            if "gemini" not in st.secrets or not st.secrets["gemini"].get("api_key"):
                raise ValueError("Missing Gemini API key in secrets")
                
            genai.configure(api_key=st.secrets["gemini"]["api_key"])
            self.model = genai.GenerativeModel('gemini-pro')
            self._initialized = True
        except Exception as e:
            self._disabled = True
            logger.error(f"Gemini init failed: {str(e)}")
    
    def _check_rate_limit(self):
        """Enforce rate limits"""
        if self._disabled:
            return False
            
        now = time.time()
        if self._rate_limit_reset and now < self._rate_limit_reset:
            return False
            
        if self._last_request_time and (now - self._last_request_time) < 1.0:
            time.sleep(1.0 - (now - self._last_request_time))
            
        return True
    
    def generate_sql(self, nl_query: str, schema_info: str = "") -> str:
        """Generate SQL with proper error handling"""
        if self._disabled:
            return "Gemini service unavailable"
            
        if not self._check_rate_limit():
            return "Gemini rate limit exceeded - please wait"
            
        try:
            prompt = f"""Generate SQL for this request:
            Schema: {schema_info}
            Request: {nl_query}
            Return ONLY the SQL query without any explanations or markdown formatting.
            SQL Query:"""
            
            response = self.model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.1,
                    "max_output_tokens": 1000
                }
            )
            
            self._last_request_time = time.time()
            return self._clean_sql(response.text)
        except Exception as e:
            if "quota" in str(e).lower() or "429" in str(e):
                self._disabled = True
                self._rate_limit_reset = time.time() + 300  # 5 minute cooldown
                return "Gemini quota exceeded - try again later"
            return f"Gemini error: {str(e)}"
    
    def _clean_sql(self, sql: str) -> str:
        """Remove quotes and markdown from SQL"""
        # Remove code blocks and quotes
        cleaned = re.sub(r"```sql|```", "", sql)
        cleaned = cleaned.strip().strip('"').strip("'").strip("`")
        # Remove potential leading keywords
        cleaned = re.sub(r"^(SQL|SELECT|WITH)\s*", "", cleaned, flags=re.IGNORECASE)
        return cleaned.strip()
    

        
# --- Core Application ---
class DataAnalyzerApp:
    
    def __init__(self):
        # Initialize authentication manager
        self.auth_manager = MySQLAuthManager()
        # Initialize AI service with default model
        self.ai = AIService("pandasai")
        self._init_session()

    def _init_session(self):
        """Comprehensive session state initialization with error handling"""
        # Client IP detection (with multiple fallback methods)
        if 'client_ip' not in st.session_state:
            st.session_state.client_ip = self._get_client_ip()

        # Model selection and AI service configuration
        model_defaults = {
            'selected_model': "pandasai",  # Internal key
            'model_options': {             # Display name -> internal key mapping
                "PandasAI": "pandasai",
                "ChatGPT": "chatgpt", 
                "Gemini": "gemini"
            }
        }

        # Authentication and user management
        auth_defaults = {
            'authentication_status': False,
            'username': None,
            'name': None,
            'user_id': None,
            'email': None,
            'roles': [],
            'token': None,
            'show_registration': False,
            'show_password_reset': False,
            'password_reset_token': None,
            'password_reset_user_id': None
        }

        # Data analysis and database
        data_defaults = {
            'data_source': "Database",
            'db_config': None,
            'uploaded_data': None,
            'query_history': [],
            'generated_sql': None,
            'db_connected': False,
            'current_db_connection': None,
            'schema_info': "",
            'last_query': None,
            'query_result': None
        }

        # UI and application state
        ui_defaults = {
            'active_tab': "Data Analysis",
            'show_sql_editor': False,
            'analysis_result': None,
            'current_page': "main",
            'sidebar_expanded': True
        }

        # Initialize all session variables with proper defaults
        for defaults in [model_defaults, auth_defaults, data_defaults, ui_defaults]:
            for key, value in defaults.items():
                if key not in st.session_state:
                    st.session_state[key] = value

        # Initialize AI service (with error handling)
        if not hasattr(self, 'ai') or not self.ai:
            try:
                # Validate selected_model exists in options
                valid_models = list(st.session_state.model_options.values())
                if st.session_state.selected_model not in valid_models:
                    st.session_state.selected_model = "pandasai"  # Reset to default
            
                self.ai = AIService(st.session_state.selected_model)
            except Exception as e:
                logger.error(f"AI service initialization failed: {str(e)}")
                st.session_state.selected_model = "pandasai"  # Fallback to default
                self.ai = AIService(st.session_state.selected_model)

    def _get_client_ip(self):
        """Safe client IP detection with multiple fallbacks"""
        ip = None
        try:
            # Method 1: Try Streamlit's runtime context
            from streamlit.runtime.scriptrunner import get_script_run_ctx
            ctx = get_script_run_ctx()
            if ctx and hasattr(ctx, 'request'):
                ip = ctx.request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        except Exception as e:
            logger.debug(f"Streamlit IP detection failed: {str(e)}")

        if not ip or ip.lower() == 'unknown':
            try:
                # Method 2: Try environment variables
                import os
                ip = os.environ.get('HTTP_X_FORWARDED_FOR', 
                                os.environ.get('REMOTE_ADDR', ''))
                ip = ip.split(',')[0].strip()
            except:
                pass

        return ip if ip and ip.lower() != 'unknown' else 'unknown'

    def _clear_session(self):
        """Complete session reset while preserving essential info"""
        # Preserve client IP and model options
        preserved_data = {
            'client_ip': st.session_state.get('client_ip', 'unknown'),
            'model_options': st.session_state.get('model_options', {
                "PandasAI": "pandasai",
                "ChatGPT": "chatgpt",
                "Gemini": "gemini"
            })
        }
    
        # Clear entire session
        st.session_state.clear()
    
        # Restore preserved data
        for key, value in preserved_data.items():
            st.session_state[key] = value
    
        # Reinitialize with defaults
        self._init_session()

    def login_ui(self):
        st.title("Enterprise Data Portal")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if username and password:
                    # Clear any existing session data before login
                    self._clear_session()
                
                    success, user_data = self.auth_manager.authenticate_user(username, password)
                    if success:
                        # Set session state
                        st.session_state['authentication_status'] = True
                        st.session_state['username'] = user_data['username']
                        st.session_state['name'] = user_data['name']
                        st.session_state['user_id'] = user_data['id']
                        st.session_state['email'] = user_data['email']
                        st.session_state['roles'] = user_data['roles']
                        # Create JWT token for API access
                        token = create_token(user_data['id'], user_data['username'], user_data['roles'])
                        st.session_state['token'] = token
                        st.success(f"Welcome back, {user_data['name']}!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.error("Please enter both username and password")
        with col2:
            st.subheader("OAuth Login")
            # OAuth Login Options (implementation simplified here)
            if st.button("Login with Google"):
                st.warning("Google OAuth integration pending")
            if st.button("Login with Microsoft"):
                st.warning("Microsoft OAuth integration pending")
            # Registration option
            st.subheader("New User")
            if st.button("Register"):
                st.session_state["show_registration"] = True
            # Password reset option
            if st.button("Forgot Password"):
                st.session_state["show_password_reset"] = True

    def registration_ui(self):
        st.title("User Registration")
        username = st.text_input("Username (min 4 characters)")
        email = st.text_input("Email")
        full_name = st.text_input("Full Name")
        password = st.text_input("Password (min 8 characters)", type="password")
        password_confirm = st.text_input("Confirm Password", type="password")
        
        # Basic validation
        if st.button("Register Account"):
            if len(username) < 4:
                st.error("Username must be at least 4 characters")
            elif len(password) < 8:
                st.error("Password must be at least 8 characters")
            elif password != password_confirm:
                st.error("Passwords do not match")
            else:
                # Get pre-authorized emails if configured
                pre_authorized = self.auth_manager.get_pre_authorized_emails()
                
                # Register user
                success = self.auth_manager.register_user(
                    username, email, full_name, password,
                    pre_authorized_emails=pre_authorized
                )
                if success:
                    st.success("Registration successful! Please log in.")
                    st.session_state['show_registration'] = False
        
        if st.button("Back to Login"):
            st.session_state['show_registration'] = False

    def password_reset_ui(self):
        st.title("Password Reset")
        if "password_reset_token" not in st.session_state:
            email = st.text_input("Enter your email")
            if st.button("Request Password Reset"):
                # Look up user by email
                user = self.auth_manager.user_exists(email)
                if user:
                    # Generate reset token
                    token = self.auth_manager.create_password_reset_token(user["user_id"])
                    if token:
                        # In a real system, you'd send an email with a reset link
                        # For this demo, we'll just store the token in session
                        st.session_state["password_reset_token"] = token
                        st.session_state["password_reset_user_id"] = user["user_id"]
                        st.success("Reset token generated. In a real system, an email would be sent.")
                else:
                    # Don't reveal if email exists or not for security
                    st.success("If your email exists in our system, you'll receive reset instructions.")
        else:
            # Token exists, show password reset form
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            if st.button("Reset Password"):
                if new_password == confirm_password:
                    if len(new_password) < 8:
                        st.error("Password must be at least 8 characters")
                    else:
                        # Verify token and reset password
                        user_id = self.auth_manager.verify_reset_token(st.session_state["password_reset_token"])
                        if user_id and user_id == st.session_state["password_reset_user_id"]:
                            success = self.auth_manager.reset_password(user_id, new_password)
                            if success:
                                st.success("Password reset successful. Please log in with your new password.")
                                # Clear reset data
                                del st.session_state["password_reset_token"]
                                del st.session_state["password_reset_user_id"]
                                st.session_state["show_password_reset"] = False
                        else:
                            st.error("Invalid or expired reset token")
                else:
                    st.error("Passwords do not match")
        if st.button("Back to Login"):
            st.session_state["show_password_reset"] = False
            if "password_reset_token" in st.session_state:
                del st.session_state["password_reset_token"]
            if "password_reset_user_id" in st.session_state:
                del st.session_state["password_reset_user_id"]

    def _db_config_ui(self, db_type: str):
        """Interface for configuring database connection settings"""
        st.sidebar.subheader("Database Configuration")
    
        # Default configuration for the selected database type
        default_config = SUPPORTED_DBS.get(db_type, {})
    
        # Host
        st.session_state.db_config = {
            "host": st.sidebar.text_input(
                "Host", 
                value=default_config.get("host", "localhost")
            ),
            "port": st.sidebar.number_input(
                "Port", 
                min_value=1, 
                max_value=65535, 
                value=default_config.get("port", 3306)
            ),
            "user": st.sidebar.text_input(
                "Username", 
                value=default_config.get("user", "")
            ),
            "password": st.sidebar.text_input(
                "Password", 
                type="password", 
                value=default_config.get("password", "")
            ),
            "database": st.sidebar.text_input(
                "Database Name", 
                value=default_config.get("database", "")
            ),
        }
    
        # Add service_name for Oracle databases
        if db_type == "Oracle":
            st.session_state.db_config["service_name"] = st.sidebar.text_input(
                "Service Name", 
                value=default_config.get("service_name", "")
            )

    def test_connection(self, db_type: str, config: Dict[str, Any]) -> Optional[Any]:
        """
        Test the database connection using the provided configuration.
        Returns the connection object if successful, otherwise None.
        """
        try:
            driver = SUPPORTED_DBS[db_type]["driver"]
            if db_type == "Oracle":
                # Oracle uses a DSN for connection
                dsn = driver.makedsn(
                    config["host"],
                    config["port"],
                    service_name=config.get("service_name"),
                )
                conn = driver.connect(
                    user=config["user"],
                    password=config["password"],
                    dsn=dsn,
                )
            else:
                # MySQL and PostgreSQL use standard connection parameters
                conn = driver.connect(
                    host=config["host"],
                    port=config["port"],
                    user=config["user"],
                    password=config["password"],
                    database=config.get("database"),
                )
            # If connection is successful, return the connection object
            return conn
        except Exception as e:
            # Log the error and return None if the connection fails
            logger.error(f"Database connection failed: {str(e)}")
            st.sidebar.error(f"Failed to connect to the database: {str(e)}")
            return None

    def main_ui(self):
        # Check authentication status
        if not st.session_state.get('authentication_status'):
            if st.session_state.get('show_registration'):
                self.registration_ui()
            elif st.session_state.get('show_password_reset'):
                self.password_reset_ui()
            else:
                self.login_ui()
            return
    
    # User info and logout
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"Welcome, **{st.session_state.get('name')}**!")
            st.write(f"Roles: {', '.join(st.session_state.get('roles', []))}")
    
        with col2:
            if st.button("Logout"):
                # Log the logout
                self.auth_manager.log_activity(
                    st.session_state.get('user_id'), 
                    'logout'
                )
                # Clear the entire session
                self._clear_session()
                st.success("Logged out successfully")
                st.rerun()
    
        
        # Role-based access control
        user_roles = st.session_state.get('roles', [])
        # Check user permissions
        permissions = self.auth_manager.get_user_permissions(st.session_state.get('user_id'))
        st.sidebar.title("Navigation")
        
        # Different menu options based on role
        if 'admin' in user_roles:
            menu = st.sidebar.radio(
                "Menu",
                ["Data Analysis", "User Management", "System Settings"]
            )
            if menu == "Data Analysis":
                self.data_analysis_ui(permissions)
            elif menu == "User Management":
                self.user_management_ui()
            elif menu == "System Settings":
                self.system_settings_ui()
        elif 'editor' in user_roles:
            menu = st.sidebar.radio(
                "Menu",
                ["Data Analysis", "My Account"]
            )
            if menu == "Data Analysis":
                self.data_analysis_ui(permissions)
            elif menu == "My Account":
                self.my_account_ui()
        else:  # viewer role
            self.data_analysis_ui(permissions, read_only=True)

    def data_analysis_ui(self, permissions, read_only=False):
        st.title("AI-Powered Data Analysis")
    
        # Model selection configuration
        model_options = {
            "PandasAI": "pandasai",
            "ChatGPT": "chatgpt",
            "Gemini": "gemini"
        }
    
        # Ensure selected_model exists and is valid
        if 'selected_model' not in st.session_state:
            st.session_state.selected_model = "pandasai"  # Default value
    
        # Convert the stored model key to display name
        current_model_display = next(
            (k for k, v in model_options.items() if v == st.session_state.selected_model),
            "PandasAI"  # Default fallback
        )
    
        # Model selection dropdown
        selected_model_display = st.sidebar.selectbox(
            "Select AI Model",
            options=list(model_options.keys()),
            index=list(model_options.keys()).index(current_model_display),
            help="Choose which AI model to use for analysis"
        )
    
        # Update the model if changed
        if model_options[selected_model_display] != st.session_state.selected_model:
            st.session_state.selected_model = model_options[selected_model_display]
            self.ai = AIService(st.session_state.selected_model)
            st.rerun()
    
        # Data source selection
        previous_source = st.session_state.get("data_source", "Database")
        current_source = st.sidebar.radio(
            "Data Source",
            ["Database", "Upload Document"],
            index=0 if st.session_state.get("data_source", "Database") == "Database" else 1,
        )
    
        # Reset relevant variables when switching data sources
        if previous_source != current_source:
            st.session_state.data_source = current_source
            st.session_state.uploaded_data = None
            st.session_state.generated_sql = None
            st.session_state.db_connected = False
            st.rerun()
    
        if st.session_state.data_source == "Database":
            self._database_ui(permissions, read_only)
        else:
            self._upload_ui(read_only)
        
        if st.session_state.uploaded_data is not None:
            self._analysis_interface(read_only)
        
    def _database_ui(self, permissions, read_only=False):
        """Interface for connecting to a database with role-based access and improved NL-to-SQL"""
        # Check if user is a viewer (and not also an admin)
        is_viewer = ('viewer' in st.session_state.get('roles', []) and 
                    'admin' not in st.session_state.get('roles', []))
    
        if is_viewer:
            st.sidebar.warning("""
            ⚠️ Viewer Role Restriction
            As a viewer, you are not authorized to access databases directly. 
            Please use the 'Upload Document' option for data analysis.
            """)
            return

        # Show only databases the user has access to
        accessible_dbs = [
            db for db, perm in permissions.items() 
            if perm["type"] == "database" and perm["read"]
        ]
    
        if not accessible_dbs:
            st.sidebar.warning("You don't have permission to access any databases")
            return

        st.sidebar.subheader("Database Connection")
    
        # Database selection
        db_name = st.sidebar.selectbox(
            "Select Database", 
            accessible_dbs,
            help="Choose from databases you have access to"
        )
    
        db_type = st.sidebar.selectbox(
            "Database Type", 
            list(SUPPORTED_DBS.keys()),
            help="Select the type of database you're connecting to"
        )

        # Database configuration
        with st.sidebar.expander("Connection Settings", expanded=True):
            # Default configuration for the selected database type
            default_config = SUPPORTED_DBS.get(db_type, {})
    
            st.session_state.db_config = {
                "host": st.text_input(
                    "Host", 
                    value=default_config.get("host", "localhost"),
                    help="Database server hostname or IP address"
                ),
                "port": st.number_input(
                    "Port", 
                    min_value=1, 
                    max_value=65535, 
                    value=default_config.get("port", 3306),
                    help="Database server port number"
                ),
                "user": st.text_input(
                    "Username",
                    value=default_config.get("user", ""),
                    help="Database username with read permissions"
                ),
                "password": st.text_input(
                    "Password", 
                    type="password",
                    value=default_config.get("password", ""),
                    help="Database password"
                ),
                "database": st.text_input(
                    "Database Name",
                    value=default_config.get("database", ""),
                    help="Name of the database/schema to connect to"
                ),  
            }   
    
        # Oracle-specific configuration
            if db_type == "Oracle":
                st.session_state.db_config["service_name"] = st.text_input(
                    "Service Name",
                    value=default_config.get("service_name", ""),
                    help="Oracle service name (not SID)"
                )

        # SQL Generation Model Selection
        sql_model = st.sidebar.selectbox(
            "SQL Generation Model",
            options=list(self.ai.sql_services.keys()),
            help="Select which AI model to use for SQL generation"
        )

        # Test connection button
        if st.sidebar.button("🔌 Test Connection", help="Verify database connection"):
            with st.spinner("Connecting to database..."):
                try:
                    conn = self.test_connection(db_type, st.session_state.db_config)
                    if conn:
                        # Extract schema information
                        schema = ConnectionManager.extract_schema(conn, db_type)
                        st.session_state.schema_info = schema
                    
                        # Store connection in session state
                        st.session_state.current_db_connection = conn
                        st.session_state.db_connected = True
                    
                        # Log successful connection
                        self.auth_manager.log_activity(
                            st.session_state.get("user_id"),
                            "database_connection",
                            f"Connected to {db_name} ({db_type})",
                        )
                        st.sidebar.success(f"✅ Successfully connected to {db_name}")
                    
                        
                    else:
                        st.session_state.db_connected = False
                        st.sidebar.error("❌ Failed to connect to database")
                except Exception as e:
                    st.session_state.db_connected = False
                    st.sidebar.error(f"Connection failed: {str(e)}")
                    logger.error(f"Database connection error: {str(e)}")

        # NL to SQL interface (only if connection was successful)
        if st.session_state.get("db_connected", False) and not read_only:
            st.subheader("Natural Language to SQL")
        
            # Display full schema in expander
            with st.expander("📋 Database Schema Information", expanded=False):
                st.json(st.session_state.schema_info)
        
            # Query input area
            nl_query = st.text_area(
                "💬 Describe what data you need:",
                height=100,
                placeholder="e.g., Show me the top 5 highest paid employees in each department",
                key="nl_query_input"
            )
        
            # Button layout
            col1, col2 = st.columns([1, 3])
        
            with col1:
                generate_btn = st.button(
                    "✨ Generate SQL", 
                    help="Convert natural language to SQL",
                    key="generate_sql_btn"
                )
        
            with col2:
                execute_btn = st.button(
                    "📊 Execute Query", 
                    help="Run the generated SQL query",
                    disabled="generated_sql" not in st.session_state,
                    key="execute_sql_btn"
                )
        
            # Handle SQL generation
            if generate_btn and nl_query:
                with st.spinner("Generating SQL query..."):
                    try:
                        generated_sql = self.ai.sql_services[sql_model].generate_sql(
                            nl_query, 
                            st.session_state.schema_info
                        )
                    
                        if generated_sql:
                            st.session_state.generated_sql = generated_sql
                        
                            # Log the generation
                            self.auth_manager.log_activity(
                                st.session_state.get("user_id"),
                                "nl_to_sql",
                                f"Generated SQL for: {nl_query}",
                            )
                        else:
                            st.error("Failed to generate SQL query")
                    except Exception as e:
                        st.error(f"SQL generation error: {str(e)}")
                        logger.error(f"SQL generation failed: {str(e)}")
        
            # Handle query execution
            if execute_btn and "generated_sql" in st.session_state:
                with st.spinner("Executing query..."):
                    try:
                        conn = st.session_state.current_db_connection
                        cursor = conn.cursor()
                    
                        # Execute query
                        cursor.execute(st.session_state.generated_sql)
                    
                        # Process results
                        results = cursor.fetchall()
                        if results:
                            columns = [desc[0] for desc in cursor.description]
                            df = pd.DataFrame(results, columns=columns)
                            st.session_state.uploaded_data = df
                        
                            # Show results
                            st.success(f"Retrieved {len(df)} rows")
                            st.dataframe(df.head(20))
                        
                            # Log the execution
                            self.auth_manager.log_activity(
                                st.session_state.get("user_id"),
                                "sql_execution",
                                f"Executed: {st.session_state.generated_sql[:200]}...",
                            )
                        else:
                            st.info("Query executed successfully but returned no results")
                    
                    except Exception as e:
                        st.error(f"Query execution failed: {str(e)}")
                        logger.error(f"Query execution error: {str(e)}")
                    
                        # Show additional debug info for connection issues
                        if "lost connection" in str(e).lower():
                            st.warning("Connection to database was lost. Please reconnect.")
                            st.session_state.db_connected = False
                    finally:
                        try:
                            cursor.close()
                        except:
                            pass
    
            # Display generated SQL if available
            if "generated_sql" in st.session_state:
                st.subheader("Generated SQL Query")
                st.code(st.session_state.generated_sql, language="sql")
            
                # Add option to edit the SQL before execution
                if st.checkbox("✏️ Edit SQL before executing", key="edit_sql_checkbox"):
                    edited_sql = st.text_area(
                        "Edit SQL Query",
                        value=st.session_state.generated_sql,
                        height=200,
                        key="sql_editor"
                    )
                    st.session_state.generated_sql = edited_sql

                    if st.button("🔍 Validate SQL Syntax", key="validate_sql_btn"):
                        if not hasattr(st.session_state, 'generated_sql') or not st.session_state.generated_sql:
                            st.error("No SQL to validate. Please generate SQL first.")
                            return
            
                        validation_result, error_message = self.validate_sql(st.session_state.generated_sql, db_type)
                        if validation_result:
                            st.success("SQL syntax is valid")
                        else:
                            st.error(f"SQL validation error: {error_message}")

    def validate_sql(sql: str, db_type: str) -> tuple[bool, str]:
        """Validate SQL syntax without executing
    
        Args:
            sql: The SQL statement to validate
            db_type: Type of database (mysql, postgresql, etc.)
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Use SQLite in-memory for validation
            dummy_engine = create_engine(
                "sqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
        
            # Try parsing the SQL
            with dummy_engine.connect() as conn:
                # For SELECT statements, we create a dummy table that might satisfy column references
                conn.execute(text("CREATE TABLE IF NOT EXISTS dummy (id INTEGER, name TEXT, value REAL, date TEXT)"))
                # Parse but don't fetch results - this will validate syntax
                conn.execute(text(f"EXPLAIN {sql}"))
            
            return True, ""
        except Exception as e:
            return False, str(e)
        
    def _upload_ui(self, read_only=False):
        """Interface for uploading files for analysis"""
        st.sidebar.subheader("File Upload Settings")
        uploaded_file = st.sidebar.file_uploader(
            "Choose a file",
            type=ALLOWED_FILE_TYPES,
            accept_multiple_files=False,
        )
        if uploaded_file:
            try:
                if uploaded_file.name.endswith(".csv"):
                    df = pd.read_csv(uploaded_file)
                elif uploaded_file.name.endswith(".xlsx"):
                    df = pd.read_excel(uploaded_file)
                elif uploaded_file.name.endswith(".parquet"):
                    df = pd.read_parquet(uploaded_file)
                else:
                    st.error(f"Unsupported file type. Please upload one of: {', '.join(ALLOWED_FILE_TYPES)}")
                    return
                st.session_state.uploaded_data = df
                st.sidebar.success(f"Loaded {len(df)} rows with {len(df.columns)} columns")
                # Log activity
                if not read_only:
                    self.auth_manager.log_activity(
                        st.session_state.get("user_id"),
                        "file_upload",
                        f"Uploaded {uploaded_file.name} ({len(df)} rows)",
                    )
            except Exception as e:
                st.error(f"File error: {str(e)}")

    def _analysis_interface(self, read_only=False):
        """Interface for analyzing data"""
        if st.session_state.uploaded_data is None:
            st.info("Please connect to a database or upload a file to begin analysis")
            return
        st.subheader("Data Preview")
        st.dataframe(st.session_state.uploaded_data.head(5))
        st.write(f"Dataset shape: {st.session_state.uploaded_data.shape[0]} rows x {st.session_state.uploaded_data.shape[1]} columns")
        # Data summary
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Column Information")
            dtype_df = pd.DataFrame(
                {
                    "Column": st.session_state.uploaded_data.columns,
                    "Data Type": st.session_state.uploaded_data.dtypes.astype(str),
                }
            )
            st.dataframe(dtype_df)
        with col2:
            st.subheader("Basic Statistics")
            numeric_cols = st.session_state.uploaded_data.select_dtypes(include=["number"]).columns
            if len(numeric_cols) > 0:
                stats_df = st.session_state.uploaded_data[numeric_cols].describe().T
                st.dataframe(stats_df)
            else:
                st.info("No numeric columns found for statistics")
        # AI Analysis section
        st.subheader("AI-Powered Data Analysis")
        analysis_prompt = st.text_area(
            "Ask a question about your data:",
            height=100,
            placeholder="e.g., What are the trends in this data? What are the top 5 values? Summarize this dataset.",
        )
        if st.button("Analyze"):
            if analysis_prompt:
                with st.spinner("Processing with AI..."):
                    analysis = self.ai.analyze_data(st.session_state.uploaded_data, analysis_prompt)
                    st.subheader("Analysis Results")
                    st.markdown(analysis)
                    # Log activity
                    if not read_only:
                        self.auth_manager.log_activity(
                            st.session_state.get("user_id"),
                            "ai_analysis",
                            f"Question: {analysis_prompt}",
                        )
                    # Add to query history
                    if "query_history" not in st.session_state:
                        st.session_state.query_history = []
                    st.session_state.query_history.append(
                        {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "question": analysis_prompt,
                            "dataset_shape": str(st.session_state.uploaded_data.shape),
                        }
                    )
            else:
                st.warning("Please enter a question to analyze the data")

    def user_management_ui(self):
        """Admin interface for user management"""
        st.title("User Management")
        # Fetch all users
        users = self.auth_manager.get_all_users()
        if not users:
            st.warning("No users found or error retrieving users")
            return
        # User table
        st.subheader("All Users")
        # Create a DataFrame for better display
        user_df = pd.DataFrame(users)
        user_df["roles"] = user_df["roles"].apply(lambda x: ", ".join(x))
        user_df["created"] = pd.to_datetime(user_df["created"]).dt.strftime("%Y-%m-%d")
        user_df["last_login"] = (
            pd.to_datetime(user_df["last_login"]).dt.strftime("%Y-%m-%d %H:%M")
            if "last_login" in user_df
            else None
        )
        st.dataframe(user_df)
        # User modification section
        st.subheader("Modify User")
        selected_user = st.selectbox(
            "Select User to Modify",
            options=[f"{u['username']} ({u['email']})" for u in users],
            format_func=lambda x: x,
        )
        if selected_user:
            username = selected_user.split(" (")[0]
            selected_user_data = next((u for u in users if u["username"] == username), None)
            if selected_user_data:
                with st.form("modify_user_form"):
                    st.write(f"Modifying user: {selected_user_data['username']}")
                    active_status = st.checkbox("Active", value=selected_user_data.get("active", True))
                    # Available roles
                    all_roles = ["admin", "editor", "viewer"]  # You might want to fetch this from the database
                    selected_roles = st.multiselect(
                        "Roles",
                        options=all_roles,
                        default=selected_user_data.get("roles", ["viewer"]),
                    )
                    password_reset = st.checkbox("Reset Password")
                    new_password = st.text_input("New Password", type="password") if password_reset else None
                    submitted = st.form_submit_button("Update User")
                    if submitted:
                        # Update roles
                        role_updated = self.auth_manager.update_user_roles(
                            selected_user_data["id"],
                            selected_roles,
                        )
                        # Reset password if requested
                        if password_reset and new_password:
                            pw_updated = self.auth_manager.reset_password(
                                selected_user_data["id"],
                                new_password,
                            )
                            if pw_updated:
                                st.success("Password updated successfully")
                            else:
                                st.error("Failed to update password")
                        if role_updated:
                            st.success(f"User {username} updated successfully")
                            # Log activity
                            self.auth_manager.log_activity(
                                st.session_state.get("user_id"),
                                "user_update",
                                f"Updated user {username}",
                            )
                        else:
                            st.error("Failed to update user")
        # New user registration
        st.subheader("Register New User")
        with st.form("register_form"):
            new_username = st.text_input("Username (min 4 characters)")
            new_email = st.text_input("Email")
            new_full_name = st.text_input("Full Name")
            new_password = st.text_input("Password (min 8 characters)", type="password")
            # Available roles
            all_roles = ["admin", "editor", "viewer"]
            new_roles = st.multiselect(
                "Roles",
                options=all_roles,
                default=["viewer"],
            )
            register_submitted = st.form_submit_button("Register User")
            if register_submitted:
                if len(new_username) < 4:
                    st.error("Username must be at least 4 characters")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters")
                else:
                    # Register user
                    success = self.auth_manager.register_user(
                        new_username, new_email, new_full_name, new_password
                    )
                    if success:
                        st.success(f"User {new_username} registered successfully")
                        # Get the new user's ID
                        new_user = self.auth_manager.user_exists(new_username)
                        if new_user and new_roles:
                            # Update roles if needed
                            self.auth_manager.update_user_roles(new_user["user_id"], new_roles)
                        # Log activity
                        self.auth_manager.log_activity(
                            st.session_state.get("user_id"),
                            "user_creation",
                            f"Created user {new_username}",
                        )
                    else:
                        st.error("Failed to register user")

    def system_settings_ui(self):
        """Admin interface for system settings"""
        st.title("System Settings")
        # System tabs
        tab1, tab2, tab3 = st.tabs(["Security Settings", "Database Connections", "Activity Logs"])
        with tab1:
            st.subheader("Security Configuration")
            # Session timeout
            session_timeout = st.number_input(
                "Session Timeout (seconds)",
                min_value=300,
                max_value=86400,
                value=SESSION_TIMEOUT,
                step=300,
            )
            # JWT expiry
            jwt_expiry = st.number_input(
                "JWT Token Expiry (seconds)",
                min_value=300,
                max_value=604800,  # 1 week
                value=JWT_EXPIRY,
                step=300,
            )
            # Pre-authorized emails
            pre_auth_emails = self.auth_manager.get_pre_authorized_emails()
            st.subheader("Pre-authorized Emails")
            st.write("Users with these emails can register without admin approval")
            email_list = st.text_area(
                "Enter emails (one per line)",
                "\n".join(pre_auth_emails),
            )
            if st.button("Update Security Settings"):
                # Here you would update the settings in the database
                st.success("Security settings updated")
                # Log activity
                self.auth_manager.log_activity(
                    st.session_state.get("user_id"),
                    "settings_update",
                    "Updated security settings",
                )
        with tab2:
            st.subheader("Database Connections")
            # Here you would list and manage database connections
            st.info("Database connection management to be implemented")
            # Example database connection form
            with st.form("db_connection_form"):
                db_name = st.text_input("Connection Name")
                db_type = st.selectbox("Database Type", SUPPORTED_DBS.keys())
                db_host = st.text_input("Host")
                db_port = st.number_input(
                    "Port",
                    value=SUPPORTED_DBS[db_type]["port"] if db_type else 0,
                )
                db_user = st.text_input("Username")
                db_password = st.text_input("Password", type="password")
                db_database = st.text_input("Database Name")
                db_submitted = st.form_submit_button("Add Connection")
                if db_submitted:
                    st.success(f"Database connection {db_name} added successfully")
                    # Here you would save the connection to the database
                    # Log activity
                    self.auth_manager.log_activity(
                        st.session_state.get("user_id"),
                        "connection_add",
                        f"Added database connection {db_name}",
                    )
        with tab3:
            st.subheader("Activity Logs")
            # Date filter
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input(
                    "Start Date", value=datetime.now() - timedelta(days=7)
                )
            with col2:
                end_date = st.date_input("End Date", value=datetime.now())
            # User filter
            users = self.auth_manager.get_all_users()
            user_options = ["All Users"] + [
                f"{u['username']} ({u['email']})" for u in users
            ]
            selected_user_filter = st.selectbox("Filter by User", options=user_options)
            # Action type filter
            action_types = [
                "All Actions",
                "login",
                "logout",
                "database_connection",
                "file_upload",
                "ai_analysis",
                "user_update",
                "user_creation",
                "settings_update",
            ]
            selected_action = st.selectbox("Filter by Action", options=action_types)
            # Fetch activity logs from the database based on filters
            # For now, show a mock activity log
            mock_logs = [
                {
                    "timestamp": "2025-04-16 10:32:15",
                    "username": "admin",
                    "action": "login",
                    "details": "Login successful",
                },
                {
                    "timestamp": "2025-04-16 11:05:22",
                    "username": "admin",
                    "action": "database_connection",
                    "details": "Connected to MySQL DB",
                },
                {
                    "timestamp": "2025-04-16 12:15:45",
                    "username": "tapiwa_garwe",
                    "action": "ai_analysis",
                    "details": "Question: What are the sales trends?",
                },
                {
                    "timestamp": "2025-04-16 14:22:10",
                    "username": "admin",
                    "action": "user_creation",
                    "details": "Created user jane_smith",
                },
                {
                    "timestamp": "2025-04-17 09:11:05",
                    "username": "irene_ndoro",
                    "action": "login",
                    "details": "Login successful",
                },
                {
                    "timestamp": "2025-04-17 09:30:18",
                    "username": "tanaka_zhou",
                    "action": "file_upload",
                    "details": "Uploaded sales_data.csv (1250 rows)",
                },
            ]
            logs_df = pd.DataFrame(mock_logs)
            st.dataframe(logs_df)
            if st.button("Export Logs"):
                # Export logs to CSV
                st.success("Logs exported successfully")

    def my_account_ui(self):
        """User interface for managing their own account"""
        st.title("My Account")
        # User info
        user_id = st.session_state.get("user_id")
        username = st.session_state.get("username")
        email = st.session_state.get("email")
        name = st.session_state.get("name")
        roles = st.session_state.get("roles", [])
        # Display user information
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Profile Information")
            st.write(f"**Username:** {username}")
            st.write(f"**Email:** {email}")
            st.write(f"**Full Name:** {name}")
            st.write(f"**Roles:** {', '.join(roles)}")
        with col2:
            st.subheader("Security")
            # Change password
            with st.form("change_password_form"):
                st.write("Change Password")
                current_password = st.text_input("Current Password", type="password")
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm New Password", type="password")
                password_submitted = st.form_submit_button("Update Password")
                if password_submitted:
                    if not current_password or not new_password or not confirm_password:
                        st.error("All fields are required")
                    elif new_password != confirm_password:
                        st.error("New passwords do not match")
                    elif len(new_password) < 8:
                        st.error("Password must be at least 8 characters")
                    else:
                        # Verify current password first
                        success, _ = self.auth_manager.authenticate_user(username, current_password)
                        if success:
                            # Reset password
                            pw_updated = self.auth_manager.reset_password(user_id, new_password)
                            if pw_updated:
                                st.success("Password updated successfully")
                                # Log activity
                                self.auth_manager.log_activity(
                                    user_id,
                                    "password_change",
                                    "Changed password",
                                )
                            else:
                                st.error("Failed to update password")
                        else:
                            st.error("Current password is incorrect")

        # Recent activity
        st.subheader("Recent Activity")
        # Fetch recent activity for this user from the database
        # For now, show a mock activity log
        mock_user_logs = [
            {
                "timestamp": "2025-04-16 10:32:15",
                "action": "login",
                "details": "Login successful",
            },
            {
                "timestamp": "2025-04-16 11:05:22",
                "action": "database_connection",
                "details": "Connected to MySQL DB",
            },
            {
                "timestamp": "2025-04-16 12:15:45",
                "action": "ai_analysis",
                "details": "Question: What are the sales trends?",
            },
            {
                "timestamp": "2025-04-17 09:11:05",
                "action": "login",
                "details": "Login successful",
            },
            {
                "timestamp": "2025-04-17 09:30:18",
                "action": "file_upload",
                "details": "Uploaded sales_data.csv (1250 rows)",
            },
        ]
        user_logs_df = pd.DataFrame(mock_user_logs)
        st.dataframe(user_logs_df)

# --- Run Application ---
def main():
    app = DataAnalyzerApp()
    app.main_ui()

if __name__ == "__main__":
    main()