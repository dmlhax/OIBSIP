## Executive Summary:

I successfully identified and exploited a fundamental SQL Injection vulnerability in the Damn Vulnerable Web Application (DVWA) running at its lowest security setting. The attack targeted the login form, allowing me to bypass authentication and gain unauthorized access without a valid username or password. This demonstration highlights a severe flaw in how the application constructs its database queries using unsanitized user input.

# Detailed Attack Walkthrough

Step 1: Environment Setup

First, I set up a controlled testing environment.

# Tool Used:

DVWA (Damn Vulnerable Web Application) as instructed 

Platform: I installed it on a local virtual machine running Kali Linux, using a pre-configured LAMP (Linux, Apache, MySQL, PHP) stack.

Configuration: After installation, I logged into DVWA and used the "Security" panel to set the application security level to "low". This setting ensures that the application's defenses are minimal, making it vulnerable to basic attacks for educational purposes.

Step 2: Reconnaissance & Target Analysis
My target was the login page (http://wangehacker.cn/DVWA/login.php). The standard function of a login form is to take a username and password, check them against a database of users, and grant access if they match.

A typical, well-written SQL query in the backend code would look something like this:

sql
SELECT * FROM users WHERE user = '$username' AND password = '$password';
If I enter admin as the username and myPassword as the password, the query becomes:

sql
SELECT * FROM users WHERE user = 'admin' AND password = 'myPassword';
If this query finds a matching row, the login is successful.

The Vulnerability: The critical flaw is that the application directly inserts my input into the query without any sanitization or validation. This allows me to "break out" of the intended data context and manipulate the query's logic.

Step 3: Crafting and Executing the SQL Injection Attack
My goal was to manipulate the query to always be true, regardless of the username or password.

Attack Vector: Username field.

Payload Entered: ' OR '1'='1' --

Password Field: I left this blank, but I could have entered anything.

Let's break down exactly how this payload works inside the SQL query.

The original, vulnerable query is:

sql
SELECT * FROM users WHERE user = '$username' AND password = '$password';
When I submit my payload, the application plugs it in directly:

$username becomes ' OR '1'='1' --

$password becomes '' (empty).

The resulting query is:

sql
SELECT * FROM users WHERE user = '' OR '1'='1' -- ' AND password = '';
Explanation of the Manipulated Query:

user = '': This part is false (we're not providing a valid username).

OR '1'='1': This is the magic. The OR operator means if either side of the condition is true, the entire WHERE clause becomes true. Since '1'='1' is always a true statement, it overrides the false user = '' condition.

--: This is the SQL comment operator. Everything that comes after it is ignored by the database. This is crucial because it effectively comments out the entire AND password = '' part of the query. The password check is completely eliminated.

The Final Effective Query:

sql
SELECT * FROM users WHERE user = '' OR '1'='1'
This query now translates to: "Select all users where 1 equals 1." This condition is true for every row in the users table. The database will return the first user it finds (which is often an administrator account).

Step 4: Capturing the Output & Result
After entering the payload (' OR '1'='1' --) into the username field and clicking "Login," the attack was successful.

# Output:

The application did not return an "invalid credentials" error.

Instead, I was successfully redirected to the main DVWA dashboard (index.php), fully authenticated as the first user in the database, which was the admin user.

# Screenshot/Evidence:
(A screenshot would be inserted here showing the payload in the username field and the subsequent successful login to the admin panel.)

Explanation of the Vulnerability
The root cause of this vulnerability is a failure to sanitize user input.

Trusting User Input: The application's PHP code naively trusts the data entered into the form fields. It takes this input and concatenates it directly into a string that forms an SQL command.

Lack of Prepared Statements: The secure way to handle database queries is to use Parameterized Queries (Prepared Statements). This technique pre-defines the SQL code and treats user input as pure data, not as part of the executable command. This makes it impossible for input to alter the query's structure.

Low Security Setting: On "low" security, DVWA intentionally does not employ any defensive coding practices, making this classic attack possible.

# Impact of this Vulnerability:
In a real-world scenario, this single flaw could lead to:

Unauthorized Access: An attacker gaining access to any user's account.

Privilege Escalation: Gaining admin-level access to an application.

Data Breach: Using this access as a foothold to extract sensitive user data (emails, hashed passwords, personal information) from the database.

# Conclusion
This project successfully demonstrated a basic yet critically dangerous SQL Injection attack. It served as a powerful reminder of the importance of secure coding practices, primarily the use of parameterized queries to separate code from data. Defending against such attacks is not optional; it is a fundamental requirement for any application that interacts with a database.

