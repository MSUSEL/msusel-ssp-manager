import sqlite3
# sqlite3 BDs are not processes, they are files.

def create_database():
    # Connect to the database (or create it if it doesn't exist)
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Create the users table
    cursor.execute('''

    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT NOT NULL,

        password TEXT NOT NULL

    )

    ''')

    # Insert an admin user
    cursor.execute('''

    INSERT INTO users (username, password)

    VALUES (?, ?)

    ''', ('admin', 'admin_password'))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()



# Run the function to create the database and users table
#create_database()
#print("Database and users table created successfully with an admin user.")

def get_user_by_username(username):
    # Connect to the database
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # Vulnerable query construction
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    # Execute the query
    cursor.execute(query)
    result = cursor.fetchone()
    
    # Close the connection
    conn.close()
    
    return result


def checkDB():
    create_database()
    print("Test database and users table created successfully with an admin user.")
    user_input = "admin' OR '1'='1"
    user = get_user_by_username(user_input)
    print(user)


# Example usage
'''user_input = "admin' OR '1'='1"
user = get_user_by_username(user_input)
print(user)'''