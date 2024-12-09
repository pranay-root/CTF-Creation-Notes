Here’s a complete guide on creating Linux-based CTF machines for your students. This includes setting up vulnerable Linux environments with different challenges that students can exploit. It’s a great way to learn practical cybersecurity skills and understand how vulnerabilities manifest in real systems.

### **Creating Linux-Based CTF Machines**

#### **1. Environment Setup**

**Virtualization vs. Containers**:
- **Virtual Machines (VMs)**: Tools like VirtualBox or VMware are commonly used to create isolated virtual machines for each CTF challenge. Each VM can have a unique environment (Ubuntu, Kali, etc.) to simulate different vulnerabilities.
- **Docker Containers**: For lightweight setups, you can use Docker containers to simulate CTF challenges. Containers allow for rapid creation and destruction of environments.

**Tools You’ll Need**:
- **VirtualBox/VMware**: For creating isolated VMs
- **Docker**: For creating isolated containers
- **Linux OS (Ubuntu, Kali Linux, etc.)**: Used for both attack and vulnerable targets
- **Netcat, SSH, HTTP servers, FTP servers**: Common services to simulate vulnerabilities

---

#### **2. Setting Up a Vulnerable Linux Machine**

**Install Linux OS**:
1. **Ubuntu**: A common choice, as it’s user-friendly and widely used in CTFs.
   - Download Ubuntu ISO from the [official website](https://ubuntu.com/download/desktop).
   - Create a VM using VirtualBox or VMware and install Ubuntu.
   - For simplicity, you can install a minimal installation without extra desktop software to keep it lean and focus on command-line tools.
  
2. **Kali Linux**: Alternatively, use Kali Linux (often preferred for penetration testing and CTFs).
   - Kali comes preloaded with many useful penetration testing tools, which may assist in both attacking and defending.
  
**Update and Configure System**:
- Once the OS is installed, ensure it is updated:
  ```bash
  sudo apt update && sudo apt upgrade
  ```
- You may also want to disable unnecessary services or ports (e.g., SSH, FTP) to restrict the scope of exploitation.

---

#### **3. Creating Vulnerabilities**

Here are several types of vulnerabilities you can create in a Linux-based CTF environment. Each one can serve as a distinct challenge for participants.

**A. Web Application Vulnerabilities**
1. **Set up a Web Server**:
   - Install Apache or Nginx:
     ```bash
     sudo apt install apache2
     ```
   - Place a simple HTML file with information about the challenge in `/var/www/html`.

2. **SQL Injection**:
   - Install MySQL and create a database for a vulnerable PHP website:
     ```bash
     sudo apt install mysql-server
     sudo apt install php libapache2-mod-php php-mysql
     ```
   - Set up a vulnerable PHP script that allows SQL injection.
   - Example: A login form with unsanitized input:
     ```php
     <?php
     $conn = new mysqli('localhost', 'root', '', 'ctf_db');
     $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
     $result = $conn->query($query);
     ?>
     ```

3. **Command Injection**:
   - Create a form or endpoint that runs system commands without sanitizing input. A common vulnerable script might be:
     ```php
     $cmd = "ls " . $_GET['dir'];
     echo shell_exec($cmd);
     ```
   - This can lead to command injection where the attacker can inject additional commands (e.g., `ls; id`).

**B. Binary Exploitation**

1. **Buffer Overflow**:
   - Create a simple C program that is vulnerable to buffer overflow:
     ```c
     #include <stdio.h>
     void vulnerable_function(char *input) {
         char buffer[64];
         strcpy(buffer, input);  // No bounds check
     }

     int main(int argc, char **argv) {
         vulnerable_function(argv[1]);
         return 0;
     }
     ```
   - Compile it with `gcc -fno-stack-protector -z execstack -o vuln vuln.c`.
   - The program is now vulnerable to buffer overflow attacks.
   - The goal for participants will be to exploit this vulnerability to execute arbitrary code.

2. **Format String Vulnerability**:
   - Create another C program that is vulnerable to format string attacks:
     ```c
     #include <stdio.h>

     int main(int argc, char **argv) {
         printf(argv[1]);
         return 0;
     }
     ```
   - Compile it with `gcc -o vuln vuln.c`.
   - By providing format specifiers like `%x` or `%n`, participants can extract sensitive data or alter program behavior.

**C. File System Vulnerabilities**

1. **Insecure File Permissions**:
   - Create a file with improper permissions:
     ```bash
     touch /tmp/flag.txt
     chmod 777 /tmp/flag.txt
     echo "flag{example}" > /tmp/flag.txt
     ```
   - Participants can exploit this by accessing the file if they gain unauthorized access to the system.

2. **Sudo Misconfigurations**:
   - Modify the sudoers file (`/etc/sudoers`) to allow a user to execute a specific command as root without a password. For example:
     ```
     username ALL=(ALL) NOPASSWD: /bin/bash
     ```
   - Participants can then execute a shell with root privileges.

**D. Cryptography Challenges**

1. **Weak Encryption**:
   - Implement weak encryption like XOR cipher or a simple Caesar cipher and challenge participants to crack the encryption.
   - For example:
     ```python
     def xor_encrypt_decrypt(input_string, key):
         return ''.join(chr(ord(c) ^ key) for c in input_string)
     ```

2. **Hash Cracking**:
   - Create challenges that involve cracking MD5, SHA1, or bcrypt hashes. Use tools like `hashcat` to generate weak password hashes and challenge participants to crack them using dictionary or brute-force attacks.

---

#### **4. Deploying and Testing Challenges**

1. **Deploy Challenges**:
   - Once you have configured and created challenges, you can deploy them to isolated VMs or Docker containers. 
   - Each VM/container should ideally be assigned a unique IP address or hostname to keep things isolated.

2. **Test Challenges**:
   - Before making the environment available to participants, test each challenge to ensure it works and is solvable. You can either solve them yourself or ask a peer to validate them.

---

#### **5. Adding Scoring and Flag Management**

- **Creating a Flag**: Each challenge should have a flag that participants must capture. Flags are often formatted like `flag{example_flag}`.
- **Automate Flag Checking**: Use scripts or CTF platforms like CTFd to check whether a participant's submission matches the correct flag. Each challenge can have a unique flag that’s checked against a database.
  
**Example**:
   - After solving a challenge, the player will submit the flag through a web interface or command-line tool, and it will be checked against a pre-stored correct value.
  
---

#### **6. Cleanup and Resetting the Environment**

After each CTF session:
1. **Reset Flags**: Ensure flags are reset and challenges are ready for the next session.
2. **Rebuild Systems**: In case participants have made significant changes, it’s good to restore the VMs or containers from snapshots or backups.

---

### **Conclusion**

Creating a Linux-based CTF machine involves setting up different types of vulnerabilities, such as web application flaws, binary exploits, and misconfigurations, within a controlled environment. 
Students will learn how to exploit these vulnerabilities and understand the common security pitfalls in real-world systems. This hands-on learning environment helps sharpen practical skills in cybersecurity.
