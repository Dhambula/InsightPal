# InsightPal
AI in Database: Automated SQL generation and data analysis through natural language
Starting the Application

Navigate to the project directory in your terminal/command prompt
Run the application using the following command:
bashstreamlit run app.py

Access the application by opening your web browser and navigating to the URL provided by Streamlit (typically http://localhost:8501)


Getting Started
First Time Setup

Start the application using streamlit run app.py
Open your web browser to the provided URL
You'll see a login interface
Use the appropriate credentials based on your assigned role


User Roles & Permissions
Viewer Role

Restricted Access: Cannot access live databases directly
Dataset Upload: Can upload and analyze CSV files
Data Analysis: Full access to PandasAI visualization tools
Security: Cannot modify database connections or user settings

Admin Role

Full Access: Can connect to and query live databases
User Management: Add, remove, and modify user permissions
Database Configuration: Set up and manage database connections
Security Settings: Configure access controls and permissions
All Viewer Features: Complete access to upload and analysis features


Viewer User Guide
Logging In

Select "Viewer" from the login interface
Enter your credentials
You'll be directed to the viewer dashboard

Uploading Datasets

Navigate to the Upload Dataset section
Click Browse Files or drag and drop your CSV file
Wait for the file to process and load
The system will display a preview of your data

Analyzing Data

Ask Natural Language Questions:

Type questions like "Show the count of gender between male and female"
Use descriptive language about what you want to see


Generate Visualizations:

Request charts: "Show a bar chart of sales by region"
Ask for summaries: "What's the average age of customers?"
Request comparisons: "Compare revenue between quarters"



Example Queries for Uploaded Data

"Show the distribution of [column_name]"
"Create a pie chart showing [category] breakdown"
"What's the correlation between [field1] and [field2]?"
"Display the top 10 [items] by [metric]"


Admin User Guide
Logging In

Select "Admin" from the login interface
Enter your administrator credentials
Access the full admin dashboard

User Management

Navigate to User Management section
Add New Users:

Click "Add User"
Enter user details and assign role (Viewer/Admin)
Set password and permissions


Modify Existing Users:

Select user from list
Update roles, permissions, or disable access


Remove Users:

Select user and confirm deletion



Database Configuration

Go to Database Settings section
Add New Connection:

Enter database host, port, username, and password
Select database type (MySQL supported)
Test connection before saving


Manage Existing Connections:

Edit connection parameters
Enable/disable connections
Delete unused connections



Security Settings

Configure access levels for different user roles
Set up database connection restrictions
Monitor user activity and access logs


Natural Language to SQL Features
Connecting to Database

Admin Only: Navigate to database connection section
Select Database: Choose from configured MySQL connections
Schema Loading: System automatically extracts database schema
Verification: Confirm connection is active and schema is loaded

Writing Natural Language Queries
Simple Queries

"Search for products in stock"
"Show all customers from New York"
"Find orders placed last month"
"List employees with salary above 50000"

Complex Queries (JOIN Operations)

"Which products did [customer_name] buy?"
"Show sales by region for each product category"
"Find customers who haven't placed orders in 6 months"
"Display top-selling products by revenue"

Aggregation Queries

"What's the total revenue by month?"
"Show average order value by customer segment"
"Count orders by status"
"Sum inventory by product category"

Query Execution Process

Input: User types natural language question
Processing: ChatGPT converts query to SQL
Execution: System runs SQL against database
Results: Data returned in tabular format
Analysis: Option to visualize results with PandasAI


Data Analysis & Visualization
Available Chart Types

Bar Charts: Compare categories or show distributions
Line Charts: Display trends over time
Pie Charts: Show proportions and percentages
Scatter Plots: Explore relationships between variables
Histograms: Display data distributions

Requesting Visualizations
After running a query, you can ask for visual analysis:

"Show a chart of the quantity of each product in stock"
"Create a line graph showing sales trends"
"Display this data as a pie chart"
"Make a scatter plot comparing price vs quantity"

Analysis Commands

"Summarize this data"
"Show statistics for [column_name]"
"Find outliers in the results"
"Calculate correlation between variables"


Troubleshooting
Common Issues
Application Won't Start

Check Python Installation: Ensure Python 3.7+ is installed
Verify Streamlit: Run pip install streamlit if needed
File Location: Ensure you're in the correct directory with app.py

Database Connection Problems

Check Credentials: Verify username, password, and host
Network Access: Ensure database server is accessible
Port Configuration: Confirm correct port number (default MySQL: 3306)
Firewall Settings: Check if firewall is blocking connection

Login Issues

Verify Credentials: Check username and password
Role Assignment: Ensure user has proper role assigned
Session Timeout: Try refreshing the page and logging in again

Query Errors

Rephrase Query: Try different wording for natural language questions
Check Schema: Ensure referenced tables/columns exist
Simplify Request: Break complex queries into smaller parts

Getting Help

Check Error Messages: Read any displayed error messages carefully
Review Logs: Look for console output when running the application
Restart Application: Close and restart with streamlit run app.py
Contact Administrator: For persistent issues, contact your system admin


Security Considerations
Role-Based Access

Viewer Restrictions: Viewers cannot access live databases
Admin Responsibilities: Admins should regularly review user access
Permission Auditing: Monitor who has access to what data

Database Security

Connection Encryption: Use SSL/TLS for database connections when possible
Credential Management: Store database credentials securely
Access Logging: Monitor database access and query patterns

Data Protection

Sensitive Data: Be cautious with sensitive information in uploads
Regular Backups: Ensure database backups are current
User Training: Train users on proper data handling procedures

Best Practices

Regular Password Updates: Change passwords periodically
Minimal Access: Give users only the access they need
Activity Monitoring: Review user activity logs regularly
Secure Uploads: Scan uploaded files for potential security issues


Support & Maintenance
Regular Maintenance

Update Dependencies: Keep Python packages updated
Monitor Performance: Check system performance regularly
Backup Data: Regular backups of user data and configurations
Security Updates: Apply security patches promptly

For Technical Support

System Administrator: Contact your organization's admin
Documentation: Refer to this manual for common issues
Error Logs: Save error messages for troubleshooting
