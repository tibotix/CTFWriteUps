# Login

Category: SQL Injection, Web
Created: Nov 18, 2020 1:44 AM
Points: 175
Solved: Yes
Subjective Difficulty: 🔥🔥

# WriteUp:

## 🔎 Research:

We are given an address that hosts something like a login form. We can submit a username and a password. The credentials are sent to `/auth.php` in a POST requests.

## 📝 Vulnerability Description:

The Login From seems to be vulnerable to a basic SQL Injection.

## 🧠 Exploit Development:

 The credentials are checked on the server side with a SQL Statement that probably looks something like this:

```php
"SELECT * FROM users_db WHERE user='" + $_POST['username'] + "' and password='" + $_POST['password'] + "' 
```

So when feeding username=`' or '1'='1` and password=`' or '1'='1` , the SQL Statement will look like this:

```sql
SELECT * FROM users_db WHERE user='' or '1'='1' and password='' or '1'='1'
```

This is a valid SQL Statement and will return the whole data record hold in users_db.

## 🔐 Exploit Programm:

```python

```

## 💥 Run Exploit:

![Login%2060b16579df3346da95c47da73eb3053c/sql_injection.png](Login%2060b16579df3346da95c47da73eb3053c/sql_injection.png)

![Login%2060b16579df3346da95c47da73eb3053c/successfull.png](Login%2060b16579df3346da95c47da73eb3053c/successfull.png)

**FLAG: nactf{sQllllllll_1m5qpr8x}**

## 🗄️ Summary / Difficulties:

This was a basic SQL Injection.

## 🗃️ Further References:

- [SQL Injection](https://www.notion.so/SQL-Injection-012b3241089c43ff87eb859b95b08b08)

## 🔨 Used Tools:

- 

---

# Notes:

-
