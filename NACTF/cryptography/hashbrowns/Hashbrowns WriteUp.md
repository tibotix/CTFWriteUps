# Hashbrowns

Category: Cryptography, General Skills
Created: Nov 8, 2020 5:14 PM
Points: 50
Solved: Yes
Subjective Difficulty: 🔥

# WriteUp:

## 🔎 Research:

We are given an MD5 hash The Details hints us that there is no salt included.

## 📝 Vulnerability Description:

When hashing a password without a salt, its likely  that this hash is in an online database.

## 🧠 Exploit Development:

We use hashtoolkit to decrypt this hash.

## 🔐 Exploit Programm:

```python

```

## 💥 Run Exploit:

![Hashbrowns%2015e7cf9ddbf045d992156151423900f8/successfull.png](Hashbrowns%2015e7cf9ddbf045d992156151423900f8/successfull.png)

**FLAG: nactf{secure_password}**

## 🗄️ Summary / Difficulties:

## 🗃️ Further References:

[](https://hashtoolkit.com/decrypt-hash/?hash=5af554431d976fdc57ea02908a8e0ce6)

## 🔨 Used Tools:

- [Hashtoolkit](https://www.notion.so/Hashtoolkit-2a97b8832aab4facb9cc108ca31e53cd)

---

# Notes:

-