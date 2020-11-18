# Grep 1

Category: General Skills, RegEx
Created: Nov 8, 2020 5:23 PM
Points: 200
Solved: Yes
Subjective Difficulty: 🔥

# WriteUp:

## 🔎 Research:

We are given a text file with a lots of Flags. The descriptiont tells us that the right flag has a specific format.

## 📝 Vulnerability Description:

## 🧠 Exploit Development:

We are using the RegEx pattern to filter the right flag.

For **nactf{** + **n|a|c 10 times**  + **any character 21 times** + **c|t|f 14 times** + **}** the command is: `cat flag.txt | grep -E "nactf{([nac]{10})(.{21})([ctf]{14})}"` .

## 🔐 Exploit Programm:

```python

```

## 💥 Run Exploit:

![Grep%201%20e99428c5ee9941988fd1b98fb5423e3d/Screenshot_2020-11-02_225347.png](Grep%201%20e99428c5ee9941988fd1b98fb5423e3d/Screenshot_2020-11-02_225347.png)

**FLAG: nactf{caancanccnxfynhtjlgllctekilyagxctftcffcfcctft}**

## 🗄️ Summary / Difficulties:

We use the RegEx pattern to filter out the real flag.

## 🗃️ Further References:

[Regex tutorial  -  A quick cheatsheet by examples](https://medium.com/factory-mind/regex-tutorial-a-simple-cheatsheet-by-examples-649dc1c3f285)

[RegExr: Learn, Build, & Test RegEx](https://regexr.com/)

## 🔨 Used Tools:

- 

---

# Notes:

-