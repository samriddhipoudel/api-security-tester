# 📊 Project Progress Log

**Student:** Samriddhi Poudel (23047345)  
**Project:** API Security Tester & Vulnerability Scanner  
**Supervisors:** Anuj Shilpakar, Rabindra Khadka

---

## Week 1: Foundation & Setup (Dec 9-15, 2025)

### Day 1 - Monday, December 9, 2025 ✅

#### ✅ Completed Tasks
- [x] GitHub repository initialized and cloned locally
- [x] Created complete project folder structure
- [x] Enhanced scanner.py with 4 security test modules:
  - Endpoint reachability check
  - HTTPS enforcement validation
  - HTTP methods testing (GET, POST, PUT, DELETE, OPTIONS)
  - Security headers analysis (X-Frame-Options, CSP, HSTS, etc.)
- [x] Created config.py for configuration management
  - Development and Production configs
  - Database settings
  - API scanner settings
  - Security test toggles
- [x] Built Flask REST API (app.py) with 6 endpoints:
  - `GET /` - Home endpoint
  - `GET /api/info` - API information
  - `GET /api/health` - Health check
  - `POST /api/scan` - Vulnerability scanning
  - `GET /api/history` - Scan history
  - `GET /api/stats` - Statistics dashboard
- [x] Created requirements.txt with all dependencies
- [x] Fixed Mac-specific port conflict (5000 → 8000)
- [x] Installed Flask, Flask-CORS, requests libraries
- [x] Successfully tested all API endpoints
- [x] Created comprehensive documentation

#### 📊 Day 1 Statistics
- **Total Commits:** 6
- **Files Created:** 4 core files (scanner.py, config.py, app.py, requirements.txt)
- **Lines of Code:** ~450+
- **API Endpoints:** 6 functional endpoints
- **Security Tests:** 4 implemented tests
- **Branches:** 1 (main)

#### 🛠️ Technologies Used
- **Language:** Python 3
- **Framework:** Flask 3.0.0
- **Libraries:** Flask-CORS, Requests
- **Tools:** VS Code, Git, Terminal
- **OS:** macOS

#### 🐛 Challenges & Solutions
| Challenge | Solution | Time Lost |
|-----------|----------|-----------|
| Port 5000 blocked by AirPlay on Mac | Changed to port 8000 | 10 mins |
| Browser cache showing old data | Used 127.0.0.1 instead of localhost | 5 mins |
| Import errors in Flask | Proper pip3 installation | 5 mins |

#### 💡 Key Learnings
1. **Flask API Development**
   - Routing and endpoint creation
   - JSON request/response handling
   - Error handling with status codes
   - CORS configuration for cross-origin requests

2. **API Security Testing**
   - HTTP methods enumeration
   - Security headers validation
   - HTTPS enforcement checking
   - Response analysis techniques

3. **Python Best Practices**
   - Class-based architecture
   - Configuration management
   - Exception handling
   - Code documentation

4. **Git Workflow**
   - Meaningful commit messages (feat:, fix:, docs:)
   - Regular commits for progress tracking
   - Pushing changes daily

#### 🧪 Testing Results
✅ Scanner module tested with public APIs (JSONPlaceholder, GitHub API)  
✅ Flask server running successfully on http://127.0.0.1:8000  
✅ All 6 API endpoints responding with correct JSON  
✅ Security tests executing and returning proper status  
✅ Error handling working for invalid inputs  

#### 📸 Evidence
- GitHub commit history: 6 commits
- Flask server screenshot (running)
- API responses in browser
- Scanner test output in terminal

#### ⏱️ Time Breakdown
- **Total Time:** 3.5 hours
  - Environment setup: 0.5 hours
  - Scanner enhancement: 1 hour
  - Flask API development: 1.5 hours
  - Testing & debugging: 0.5 hours
  - Documentation: 0.5 hours (this log)

#### 📝 Supervisor Updates
- **Status:** On track
- **Blockers:** None
- **Help Needed:** None currently

---

### Day 2 - Tuesday, December 10, 2025 🚀

#### 📅 Planned Tasks
- [ ] Install MySQL or PostgreSQL database
- [ ] Design database schema (ERD diagram)
- [ ] Create database tables:
  - `users` - User management
  - `api_endpoints` - Saved API configurations
  - `scan_results` - Scan history and results
  - `vulnerabilities` - Detected vulnerabilities
  - `alerts` - Alert notifications
- [ ] Create models.py with SQLAlchemy ORM
- [ ] Test database connection from Flask
- [ ] Implement basic CRUD operations
- [ ] Create database migrations

#### 🎯 Goals for Day 2
- Functional database connection
- All tables created
- Basic data insertion/retrieval working
- 3-4 commits to GitHub

#### ⏰ Estimated Time
- **Total:** 3-4 hours
  - Database installation: 0.5 hours
  - Schema design: 1 hour
  - Models creation: 1 hour
  - Testing: 0.5 hours
  - Documentation: 0.5 hours

---

## 📊 Week 1 Progress Summary

**Days Completed:** 1/7  
**Overall Progress:** 14% of Week 1  

### Cumulative Stats
- **Total Commits:** 6
- **Total Files:** 4
- **Total LOC:** 450+
- **Total Time:** 3.5 hours

### Next Milestones
- ✅ Day 1: Foundation & Setup (Complete)
- 🔄 Day 2: Database Design (In Progress)
- ⏳ Day 3-4: Database Implementation
- ⏳ Day 5: Frontend Basic UI
- ⏳ Day 7: Week 1 Review & Documentation

---

## 📞 Contact Log
- **Last Update to Supervisors:** Dec 9, 2025 (Evening)
- **Next Check-in:** Dec 10, 2025 (Evening)
- **Weekly Meeting:** Friday, Dec 13, 2025

---

**Notes:**
- Project is on schedule ✅
- No major blockers
- Good momentum on Day 1
- Ready for database implementation

---

*Last Updated: December 10, 2025 - Morning*