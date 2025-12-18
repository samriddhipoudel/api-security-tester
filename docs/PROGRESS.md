# 📊 Project Progress Log

**Student:** Samriddhi Poudel (23047345)  
**Project:** API Security Tester & Vulnerability Scanner  
**Supervisors:** Anuj Shilpakar, Rabindra Khadka

---

## Week 1: Foundation & Setup (Dec 9–13, 2025)

### Day 1 – Tuesday, Dec 9 ✅

**Completed Tasks**
- Initialized GitHub repository and cloned locally
- Created project folder structure
- Enhanced `scanner.py` with 4 security tests:
  - Endpoint reachability
  - HTTPS enforcement
  - HTTP methods testing (GET, POST, PUT, DELETE, OPTIONS)
  - Security headers validation (X-Frame-Options, CSP, HSTS)
- Created `config.py` for configuration management
  - Development & Production configs
  - Database settings
  - API scanner settings
  - Security test toggles
- Built Flask REST API (`app.py`) with 6 endpoints
  - `GET /` – Home
  - `GET /api/info` – API info
  - `GET /api/health` – Health check
  - `POST /api/scan` – Vulnerability scanning
  - `GET /api/history` – Scan history
  - `GET /api/stats` – Statistics
- Created `requirements.txt` with dependencies
- Fixed Mac port conflict (5000 → 8000)
- Installed Flask, Flask-CORS, requests
- Tested all endpoints successfully
- Created documentation

**Day 1 Stats**
- Commits: 6
- Files created: 4 core files
- Lines of code: ~450+
- API endpoints: 6 functional
- Security tests: 4 implemented

**Technologies Used:** Python 3, Flask, Flask-CORS, Requests, VS Code, Git, macOS

**Challenges & Solutions**
| Challenge | Solution | Time Lost |
|-----------|----------|-----------|
| Port 5000 blocked by AirPlay | Changed to 8000 | 10 mins |
| Browser cache showing old data | Used 127.0.0.1 instead of localhost | 5 mins |
| Import errors in Flask | Proper pip3 installation | 5 mins |

**Key Learnings**
- Flask API development & routing
- JSON request/response handling
- CORS configuration
- HTTP methods and headers validation
- Class-based Python architecture & exception handling
- Git workflow & documentation

**Testing Results**
- Scanner tested with public APIs (JSONPlaceholder, GitHub API)
- Flask server running at http://127.0.0.1:8000
- All 6 endpoints responding correctly
- Security tests executing properly
- Error handling verified

**Time Breakdown:** 3.5 hours  
- Environment setup: 0.5h  
- Scanner enhancement: 1h  
- Flask API: 1.5h  
- Testing & debugging: 0.5h  
- Documentation: 0.5h

**Supervisor Update:** On track, no blockers

---

### Day 2 – Wednesday, Dec 10 ✅

**Completed Tasks**
- Installed MySQL (Homebrew) & configured root password
- Designed database schema with 6 tables
- Created `schema.sql` & `ERD_DESIGN.md`
- Created `models.py` with SQLAlchemy ORM
- Updated `config.py` with MySQL URI
- Updated `app.py` for database integration:
  - `GET /api/endpoints`, `POST /api/endpoints`
  - `POST /api/scan`, `GET /api/scans`, `GET /api/stats`
- Tested endpoints & database connection

**Day 2 Stats**
- Commits: 4
- New files: 3
- Updated files: 2
- Database tables: 6
- API endpoints: 8
- Lines of code: ~300+

**Technologies Used:** MySQL 9.5.0, SQLAlchemy, Flask-SQLAlchemy, PyMySQL

**Key Learnings**
- Database design & ER modeling
- Foreign key & relationships
- SQLAlchemy ORM usage
- Flask-DB integration

**Testing Results**
- MySQL installed & running
- Database created & connected
- Tables created successfully
- API endpoints storing/retrieving data
- Scan results persisted

**Time Breakdown:** 4 hours

**Supervisor Update:** Ahead of schedule, no blockers

---

### Day 3 – Friday, Dec 12 ✅

**Completed Tasks**
- Created `index.html` frontend with UI
- Added responsive design & sections:
  - Header, hero, scan form, results, saved endpoints, footer
- Created `styles.css` with modern styling & animations
- Updated `app.py` to serve static files
- Tested frontend rendering & responsiveness

**Day 3 Stats**
- Commits: 1
- New files: 2
- Updated files: 1
- Lines of code: ~600+
- HTML elements: 50+
- CSS classes: 80+

**Key Learnings**
- Semantic HTML & responsive CSS
- Grid & Flexbox layouts
- Color psychology & UI/UX
- Flask static file handling

**Testing Results**
- HTML renders correctly
- CSS styling applied
- Layout responsive on mobile
- Forms & buttons functional
- No console errors

**Time Breakdown:** 3 hours

**Supervisor Update:** On schedule, no blockers

---

### Day 4 – Saturday, Dec 13 ✅

**Completed Tasks**
- Created `app.js` for frontend functionality (350+ lines)
- Implemented async fetch API calls
- Dynamic DOM rendering for results
- Form validation & error handling
- Notifications system with animations
- Functions: checkConnection, handleScan, handleSaveEndpoint, loadSavedEndpoints, displayResults, showNotification
- Verified frontend-backend-database integration
- Took 7 screenshots for documentation

**Day 4 Stats**
- Commits: 2
- New files: 1
- JS lines: 350+
- Functions: 12
- API integrations: 4
- Features implemented: 8
- Testing time: 1h

**Key Learnings**
- Asynchronous JS (async/await)
- DOM manipulation & template literals
- State management (loading, buttons, results)
- API integration & error handling
- Code organization & helper functions

**Testing Results**
- End-to-end workflow verified
- All API endpoints working
- Dynamic results displayed with color-coded badges
- Data saved & loaded from database
- Browser compatibility tested (Chrome/Brave)

**Time Breakdown:** 3.5 hours

**Major Milestone:** COMPLETE WORKING PROTOTYPE

**Supervisor Update:** Milestone achieved, confidence very high

---

## Weekend Break (Dec 14–15, 2025)

- Dec 14: Full rest day
- Dec 15: Planning & documentation updates
- Purpose: Recharge & organize Week 2 tasks

---

## Week 1 Summary

- Days worked: 4
- Commits: 13+
- Files: 8
- Lines of code: ~1,700+
- API endpoints: 8
- Database tables: 6
- Security tests: 4
- Technologies: Python, Flask, SQLAlchemy, MySQL, HTML, CSS, JS
- Major milestone: Full working prototype delivered
- Confidence: Very high

---

## Week 2: Advanced Security Testing (Dec 16–20, 2025)

### Day 1 – Tuesday, Dec 16 ✅

**Completed Tasks**
- Added Test 5: Broken Authentication
- Added Test 6: SQL Injection Detection
- Updated `scanner.py` to run 6 tests
- Tested with GitHub API
- Verified Flask integration

**Day 1 Stats**
- Commits: 2
- New functions: 2
- Lines added: ~150+
- Total tests: 6
- Time: 2.5h

**Key Learnings**
- Authentication testing techniques
- SQL injection payloads & error detection
- Test design & performance balancing

**Testing Results**
- All 6 tests working
- Performance: ~5s for full scan

**Supervisor Update:** 2/6 new tests complete, no blockers

---

### Day 2 – Wednesday, Dec 17 ✅

**Completed Tasks**
- Added Test 7: XSS Detection
- Added Test 8: Rate Limiting Check
- Updated `scanner.py` to run 8 tests
- Tested with GitHub API

**Day 2 Stats**
- Commits: 1
- New functions: 2
- Lines added: ~120+
- Total tests: 8
- Time: 2h

**Key Learnings**
- XSS payloads & output sanitization
- API throttling & rate limit testing
- Error handling & performance optimization

**Testing Results**
- All 8 tests working
- Performance: ~8s for full scan

**Supervisor Update:** Week 2 Day 2 complete, 4/6 new tests done, no blockers

---

### Week 2 Milestone Achieved

- All 10 planned security tests implemented
- Ahead of schedule by 3 weeks
- Next steps:
  - Test with multiple APIs
  - Fix bugs
  - Optimize performance
  - Update documentation & screenshots
