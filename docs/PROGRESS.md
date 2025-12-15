# 📊 Project Progress Log

**Student:** Samriddhi Poudel (23047345)  
**Project:** API Security Tester & Vulnerability Scanner  
**Supervisors:** Anuj Shilpakar, Rabindra Khadka

---

## Week 1: Foundation & Setup (Dec 9-13, 2025)

### Day 1 - Tuesday, December 9, 2025 ✅

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
  - Documentation: 0.5 hours

#### 📝 Supervisor Updates
- **Status:** On track
- **Blockers:** None
- **Help Needed:** None currently

---

### Day 2 - Wednesday, December 10, 2025 ✅

#### ✅ Completed Tasks
- [x] Installed MySQL database (Homebrew)
- [x] Configured MySQL with root password
- [x] Designed complete database schema with 6 tables
- [x] Created database/schema.sql with:
  - users table (authentication)
  - api_endpoints table (saved APIs)
  - scans table (scan history)
  - vulnerabilities table (test results)
  - alerts table (notifications)
  - scan_schedules table (automation)
- [x] Created database/ERD_DESIGN.md documentation
- [x] Created backend/models.py with SQLAlchemy ORM
  - 6 model classes matching database tables
  - Relationships and foreign keys configured
  - to_dict() methods for JSON serialization
- [x] Updated backend/config.py with MySQL connection string
- [x] Enhanced backend/app.py with database integration:
  - GET /api/endpoints - List saved APIs
  - POST /api/endpoints - Save new API
  - POST /api/scan - Scan with database storage
  - GET /api/scans - Scan history
  - GET /api/stats - Statistics from database
- [x] Fixed SQLAlchemy text() query issue
- [x] Tested all endpoints successfully
- [x] Database connection verified

#### 📊 Day 2 Statistics
- **Total Commits:** 4
- **New Files:** 3 (schema.sql, ERD_DESIGN.md, models.py)
- **Updated Files:** 2 (config.py, app.py)
- **Database Tables:** 6 created
- **API Endpoints:** 8 total (2 new DB endpoints)
- **Lines of Code:** ~300+ new

#### 🛠️ Technologies Used
- MySQL 9.5.0 (Homebrew)
- SQLAlchemy ORM
- Flask-SQLAlchemy
- PyMySQL (MySQL connector)

#### 🐛 Challenges & Solutions
| Challenge | Solution | Time Lost |
|-----------|----------|-----------|
| MySQL installation on Mac | Used Homebrew for clean install | 15 mins |
| Root password authentication | Used mysql_secure_installation | 10 mins |
| SQLAlchemy text() deprecation | Added explicit text() import | 5 mins |
| Database folder was a file | Deleted file, created folder | 2 mins |

#### 💡 Key Learnings
1. **Database Design**
   - Entity-Relationship modeling
   - Foreign key constraints
   - One-to-Many relationships
   - Index optimization

2. **SQLAlchemy ORM**
   - Model class creation
   - Relationship definitions
   - Session management
   - Query building

3. **Database Integration**
   - Flask-SQLAlchemy setup
   - Database URI configuration
   - Migration considerations
   - Connection testing

4. **MySQL Administration**
   - Installation via Homebrew
   - Service management
   - User authentication
   - Database creation

#### 🧪 Testing Results
✅ MySQL installed and running  
✅ Database `api_security_db` created  
✅ All 6 tables created successfully  
✅ Flask connects to database  
✅ Health check shows "database: connected"  
✅ Can save API endpoints to database  
✅ Scan results saved to database  

#### 📊 Database Schema
#### 🎯 API Endpoints Added
- `GET /api/endpoints` - List all saved APIs
- `POST /api/endpoints` - Save new API configuration
- `GET /api/scans` - Get scan history from database
- `GET /api/stats` - Get statistics (counts)

#### ⏱️ Time Breakdown
- **Total Time:** 4 hours
  - MySQL installation & setup: 0.5 hours
  - Database schema design: 1 hour
  - Models.py creation: 1 hour
  - App.py database integration: 1 hour
  - Testing & debugging: 0.5 hours

#### 📝 Supervisor Updates
- **Status:** Ahead of schedule
- **Blockers:** None
- **Help Needed:** None

---

### Day 3 - Friday, December 12, 2025 ✅

#### ✅ Completed Tasks
- [x] Created frontend/index.html with complete user interface
  - Header with logo and status indicator
  - Hero section with project description
  - API scan form with validation
  - HTTP method selector (GET, POST, PUT, DELETE)
  - Loading indicator with animation
  - Results section with stats grid
  - Saved endpoints list section
  - Footer with developer info
- [x] Created frontend/css/styles.css with modern styling
  - Responsive design (mobile-friendly)
  - Gradient backgrounds
  - Card-based layout
  - Custom form inputs and buttons
  - Color-coded severity badges
  - Smooth animations and transitions
  - Loading spinner animation
  - Stats cards with different states
- [x] Updated backend/app.py to serve static files
  - Added routes for HTML serving
  - Added routes for CSS files
  - Added routes for JS files (prepared for tomorrow)
  - Separated API routes from frontend routes
- [x] Tested complete frontend rendering
- [x] Verified responsive design on different screen sizes

#### 📊 Day 3 Statistics
- **Total Commits:** 1 (large commit)
- **New Files:** 2 (index.html, styles.css)
- **Updated Files:** 1 (app.py)
- **Lines of Code:** ~600+ (HTML + CSS)
- **HTML Elements:** 50+
- **CSS Classes:** 80+
- **Responsive Breakpoints:** 2

#### 🎨 Design Features Implemented
- **Color Scheme:**
  - Primary: Purple gradient (#667eea → #764ba2)
  - Success: Green (#10b981)
  - Danger: Red (#ef4444)
  - Warning: Orange (#f59e0b)
  
- **UI Components:**
  - Sticky header with blur effect
  - Gradient hero section
  - Card-based content layout
  - Form inputs with focus states
  - Primary and secondary buttons
  - Loading spinner
  - Stats grid (4 columns)
  - Result items with severity colors
  - Empty state messages

- **Animations:**
  - Button hover effects
  - Loading spinner rotation
  - Slide-up results animation
  - Status dot pulse animation
  - Smooth transitions (0.3s)

#### 🛠️ Technologies Used
- HTML5 (Semantic markup)
- CSS3 (Custom properties, Grid, Flexbox)
- CSS Animations
- Responsive Design
- Flask static file serving

#### 💡 Key Learnings
1. **Frontend Development**
   - Semantic HTML structure
   - CSS custom properties (variables)
   - CSS Grid and Flexbox layouts
   - Responsive design principles
   - Form styling and UX

2. **Flask Static Files**
   - send_from_directory() usage
   - Static file routing
   - Serving multiple file types
   - Path handling

3. **UI/UX Design**
   - Color psychology for security app
   - Visual hierarchy
   - Loading states
   - Empty states
   - Accessibility considerations

#### 🧪 Testing Results
✅ HTML renders correctly  
✅ CSS loads and applies styling  
✅ Layout responsive on mobile  
✅ All sections visible  
✅ Forms display properly  
✅ Buttons styled correctly  
✅ Colors and gradients working  
✅ No console errors  

#### 📱 Responsive Design
- **Desktop:** Full grid layout (4 columns)
- **Tablet:** Adjusted grid (2-3 columns)
- **Mobile:** Single column, stacked layout

#### 🎯 UI Sections Created
1. Header (sticky, with status)
2. Hero section (with gradient background)
3. Scan form section (input, method, description)
4. Loading indicator (hidden by default)
5. Results section (stats + detailed results)
6. Saved endpoints section
7. Footer (developer info)

#### ⏱️ Time Breakdown
- **Total Time:** 3 hours
  - HTML structure: 1 hour
  - CSS styling: 1.5 hours
  - Flask routing: 0.5 hours

#### 📝 Supervisor Updates
- **Status:** On schedule
- **Blockers:** None
- **Help Needed:** None

---

### Day 4 - Saturday, December 13, 2025 ✅

#### ✅ Completed Tasks
- [x] Created frontend/js/app.js with complete JavaScript functionality (350+ lines)
- [x] Implemented asynchronous API calls using fetch() and async/await
- [x] Built dynamic DOM manipulation for real-time results display
- [x] Added form validation and error handling
- [x] Implemented notification system with animations
- [x] Created functions for:
  - checkConnection() - Backend health monitoring
  - handleScan() - Execute security scans
  - handleSaveEndpoint() - Save API configurations
  - loadSavedEndpoints() - Fetch and display saved APIs
  - displayResults() - Dynamic result rendering
  - showNotification() - Toast notifications
- [x] Tested complete end-to-end workflow
- [x] Verified frontend-backend-database integration
- [x] Took 7 project screenshots for documentation
- [x] Fixed Flask static file serving
- [x] All API endpoints working correctly

#### 📊 Day 4 Statistics
- **Total Commits:** 2
- **New Files:** 1 (app.js)
- **Lines of JavaScript:** 350+
- **Functions Created:** 12
- **API Integrations:** 4 endpoints connected
- **Features Implemented:** 8
- **Screenshots Taken:** 7
- **Testing Time:** 1 hour

#### 🎨 JavaScript Features Implemented

**Core Functions:**
1. `checkConnection()` - Checks backend health on page load
2. `setupEventListeners()` - Registers all event handlers
3. `handleScan()` - Processes scan form submission
4. `handleSaveEndpoint()` - Saves API to database
5. `loadSavedEndpoints()` - Fetches saved APIs from backend
6. `loadEndpointToForm()` - Populates form with saved data
7. `displayResults()` - Renders scan results dynamically
8. `clearResults()` - Clears result section
9. `showLoading() / hideLoading()` - Loading state management
10. `showResults() / hideResults()` - Result visibility control
11. `showNotification()` - Toast notification system

**UI State Management:**
- Loading indicators during API calls
- Button disable/enable during operations
- Smooth scroll to results
- Dynamic color-coded result items
- Stats calculation and display
- Empty state handling

**Data Handling:**
- JSON request/response parsing
- Form data collection and validation
- URL format validation
- Error handling for failed requests
- Dynamic HTML generation with template literals

#### 🛠️ Technologies Used
- **JavaScript ES6+** (async/await, arrow functions, template literals)
- **Fetch API** (HTTP requests)
- **DOM Manipulation** (getElementById, innerHTML, addEventListener)
- **CSS Animations** (dynamically injected)
- **Event Handling** (form submit, button clicks)

#### 🧪 Testing Results

**End-to-End Test Case:**
- ✅ Entered URL: https://api.github.com
- ✅ Clicked "Start Security Scan"
- ✅ Loading spinner displayed
- ✅ Scan completed in 3 seconds
- ✅ Results displayed with correct colors:
  - ✅ Reachability: PASS (green)
  - ✅ HTTPS: PASS (green)
  - ⚠️ HTTP Methods: WARNING (yellow)
  - ❌ Headers: FAIL (red)
- ✅ Stats updated: 4 total, 2 passed, 1 failed, 1 warning
- ✅ Saved endpoint to database
- ✅ Endpoint appeared in saved list
- ✅ "Load" button populated form correctly
- ✅ No JavaScript errors in console

**API Endpoints Tested:**
- ✅ POST /api/scan - Working
- ✅ POST /api/endpoints - Working
- ✅ GET /api/endpoints - Working
- ✅ GET /api/health - Working

**Browser Compatibility:**
- ✅ Chrome/Brave - Working perfectly
- ⏳ Safari - Not tested yet
- ⏳ Firefox - Not tested yet

#### 💡 Key Learnings

**1. Asynchronous JavaScript:**
- Async/await makes code readable vs callback hell
- Try-catch blocks handle promise rejections
- Fetch API returns promises that need await
- Must use async keyword on function to use await

**2. DOM Manipulation:**
- Template literals (backticks) for clean HTML generation
- innerHTML for quick updates (careful with XSS)
- querySelector vs getElementById performance
- Event delegation for dynamic elements

**3. State Management:**
- Show/hide patterns for UI elements
- Disable buttons during operations (prevent double-submit)
- Loading states improve UX
- Clear feedback with notifications

**4. API Integration:**
- Content-Type header required for JSON
- JSON.stringify() converts objects to strings
- response.json() parses JSON from server
- Error handling for network failures

**5. Code Organization:**
- Separate functions for each responsibility
- Constants at top for easy configuration
- Event listeners grouped in setup function
- Helper functions at bottom

#### 🎨 UI/UX Enhancements
- Toast notifications slide in from right
- Auto-dismiss after 3 seconds
- Loading spinner with smooth animation
- Disabled buttons during operations
- Color-coded severity (green/yellow/red)
- Smooth scroll to results section
- Empty state messages for no data
- Connection status indicator with pulse animation

#### 🐛 Issues Fixed Today
- Flask static file routing for JS files
- Form preventDefault to stop page reload
- Notification z-index for proper stacking
- Result item color classes matching status
- API URL validation before submission

#### 🎯 Complete Workflow Verified

**User Flow:**
1. User opens http://127.0.0.1:8000 ✅
2. Sees "Connected" status (green) ✅
3. Fills form with API details ✅
4. Clicks "Start Security Scan" ✅
5. Loading spinner appears ✅
6. Results display after 3-5 seconds ✅
7. Stats show test summary ✅
8. Each test has color badge ✅
9. Can save endpoint ✅
10. Saved endpoint appears in list ✅
11. Can load endpoint back to form ✅

**Data Flow:**