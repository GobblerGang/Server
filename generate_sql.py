import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from sqlalchemy import create_engine
from sqlalchemy.schema import CreateTable
from sqlalchemy.dialects import mysql

# Import your models (this registers them with the SQLAlchemy metadata)
from app.models import db # Import db
from app.models import User, File, UserKeys, PAC # Import all your defined models

# Get the database URI from environment variables
db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT", "3306") # Default to 3306 if not set
db_name = os.getenv("DB_NAME")

# Construct a dummy connection string for dialect inference
dummy_db_uri = f'mysql+mysqlconnector://{db_user or "user"}:{db_pass or "pass"}@{db_host or "localhost"}:{db_port or "3306"}/{db_name or "db"}'

# Create a dummy engine just to get the MySQL dialect
engine = create_engine(dummy_db_uri)

# Get the MySQL dialect
dialect = mysql.dialect()

# Open a file to write the SQL schema
output_file = "server_db_schema.sql"
with open(output_file, 'w') as f:
    # Iterate over all tables in the metadata and generate CREATE TABLE statements
    # SQLAlchemy's metadata should now include all defined models
    for table in db.metadata.sorted_tables:
        # Generate CREATE TABLE statement for the table
        create_table_statement = str(CreateTable(table).compile(dialect=dialect)).strip()
        f.write(create_table_statement + ";\n\n")

print(f"SQL schema written to {output_file}")
print("You can now apply this schema to your MySQL database using:")
print(f"mysql -u {{db_user or \"your_mysql_user\"}} -p {{db_name or \"your_database_name\"}} < {output_file}") 