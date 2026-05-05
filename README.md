# SigHunt CTF Platform

## Relased in Defcon Singapore Demo Labs, 28-30 April 2026

## Setup

### 1. MySQL
```sql
CREATE DATABASE ctf_platform CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ctf_user'@'localhost' IDENTIFIED BY 'ctf_password';
GRANT ALL PRIVILEGES ON ctf_platform.* TO 'ctf_user'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Install
```bash
pip install -r requirements.txt
```


### 3. Run
```bash
python app.py
```
Open http://localhost:8050

**Default admin:** `admin@ctf.local` / `Admin@1234`

### (Optional) 4 Add Sample Challenges
To Add Sample Challenges Use sql file challenges_export_2026-04-20_112510.sql with following command
Note that it uses default admin id = 1 as challenge creator ID so run projects atleast once before importing this sql file.

```bash
mysql -u ctf_user -p ctf_platform < challenges_export_2026-04-20_112510.sql 
```

## Project Structure
```
ctf_platform/
├── app.py
├── requirements.txt
├── challenges_logs/     <- uploaded log files
├── pages/
│   ├── home.py
│   ├── login.py
│   ├── register.py
│   ├── dashboard.py
│   ├── challenges.py
│   ├── challenge_solve.py
│   ├── leaderboard.py
│   ├── profile.py
│   ├── change_password.py
│   ├── admin_create.py
│   └── admin_manage.py
└── utils/
    ├── db.py
    ├── auth.py
    └── sigma_engine.py
    └── win_log_generator.py
```