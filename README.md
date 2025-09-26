# Censys Host Summarizer

A comprehensive web application for analyzing and summarizing host data from Censys datasets. The application provides intelligent host analysis with AI-powered summaries, risk assessment, and detailed security insights.

## Features

- **Dataset Upload**: Upload JSON datasets containing host information
- **Individual Host Analysis**: Get detailed summaries for specific IP addresses
- **Batch Processing**: Analyze all hosts in a dataset simultaneously
- **AI-Powered Summaries**: Generate intelligent summaries using OpenAI GPT or Google Gemini
- **Risk Assessment**: Automatic risk level calculation based on vulnerabilities and services
- **Real-time Status**: Monitor backend health and API key status
- **Responsive Design**: Modern, mobile-friendly interface
- **Comprehensive Testing**: Unit, integration, and end-to-end tests

## Architecture

### Backend (FastAPI)
- **Framework**: FastAPI with automatic API documentation
- **AI Integration**: OpenAI GPT-4 and Google Gemini support
- **Data Processing**: Intelligent extraction of host information from various JSON formats
- **Risk Calculation**: Advanced risk assessment based on CVSS scores, service exposure, and threat intelligence
- **Error Handling**: Comprehensive error handling with detailed logging

### Frontend (React)
- **Framework**: React 19 with modern hooks
- **UI Components**: Custom reusable components with consistent styling
- **State Management**: Efficient state management with proper cleanup
- **Error Handling**: User-friendly error messages and loading states
- **Responsive Design**: Mobile-first design with modern CSS

### Testing
- **Backend Tests**: Comprehensive unit and integration tests with pytest
- **Frontend Tests**: Component and utility tests with Jest and React Testing Library
- **E2E Tests**: Full user workflow tests with Playwright
- **Centralized Testing**: All tests organized in the `tests/` directory

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Praneeth-1312/Censys.git censys_exercise
   cd censys_exercise
   ```

### Backend Setup

1. **Create virtual environment**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables** (optional):
   ```bash
   # Create .env file in backend directory
   GEMINI_API_KEY=your_gemini_api_key_here
   OPENAI_API_KEY=your_openai_api_key_here
   ```

4. **Run the backend**:
   ```bash
   python -m uvicorn main:app --reload --port 8000
   ```

The backend will be available at `http://localhost:8000` with automatic API documentation at `http://localhost:8000/docs`.

### Frontend Setup

1. **Install dependencies**:
   ```bash
   cd frontend
   npm install
   ```

2. **Start the development server**:
   ```bash
   npm start
   ```

The frontend will be available at `http://localhost:3000`.

## Usage

### 1. Upload Dataset
- Click "Select File" and choose a JSON file containing host data
- The application supports various JSON formats:
  - Array of host objects: `[{"ip": "1.2.3.4", ...}, ...]`
  - Object with hosts array: `{"hosts": [{"ip": "1.2.3.4", ...}, ...]}`
  - Object with host objects: `{"host1": {"ip": "1.2.3.4", ...}, ...}`

### 2. Individual Host Analysis
- Enter an IP address in the "Summarize Individual Host" section
- Click "🚀 Summarize" to get a detailed analysis
- The summary includes risk assessment, exposed services, vulnerabilities, and recommendations

### 3. Batch Analysis
- Click "🚀 Summarize All Hosts" to analyze all hosts in the dataset
- View comprehensive results with processing time and statistics

### 4. Status Monitoring
- Click "📊 Show Status" to view:
  - Backend health status
  - AI service availability
  - Dataset statistics
  - Upload timestamp

## API Endpoints

### Core Endpoints
- `GET /` - Root endpoint with version info
- `GET /health` - Health check with dataset status
- `POST /upload_dataset/` - Upload JSON dataset
- `GET /get_uploaded_data/` - Get current dataset info
- `POST /summarize_host/` - Summarize individual host
- `GET /summarize_all/` - Summarize all hosts
- `GET /stats/` - Get dataset statistics
- `GET /check_key/` - Check AI API key status

### Response Models
All endpoints return structured JSON responses with proper error handling and validation.

## Testing

### Backend Tests
```bash
cd tests/backend
# Make sure backend virtual environment is activated
pytest test_main.py -v
```

### Frontend Tests
```bash
cd frontend
# Make sure frontend dependencies are installed
npm test
```

### End-to-End Tests
```bash
cd tests/e2e
npm install
npm run install  # Install Playwright browsers
npm test
```

### All Tests (from project root)
```bash
# Run all tests with the centralized test runner
tests/run-all-tests.sh  # Unix/Linux/Mac
tests/run-all-tests.bat # Windows Command Prompt
.\tests/run-all-tests.bat # Windows PowerShell
```

## Data Format

### Expected Host Object Structure
```json
{
  "ip": "192.168.1.100",
  "ip_address": "192.168.1.100",  // Alternative IP field
  "location": {
    "country": "United States",
    "city": "New York",
    "region": "NY"
  },
  "autonomous_system": {
    "asn": 12345,
    "name": "Example ISP",
    "country_code": "US"
  },
  "services": [
    {
      "port": 22,
      "service": "ssh",
      "product": "OpenSSH 8.2",
      "banner": "SSH-2.0-OpenSSH_8.2",
      "vulnerabilities": [
        {
          "id": "CVE-2021-44228",
          "severity": "Critical",
          "cvss_score": 10.0,
          "description": "Log4j vulnerability"
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "severity": "Critical",
      "cvss_score": 10.0,
      "description": "Log4j vulnerability"
    }
  ],
  "threat_intelligence": {
    "security_labels": ["malware", "c2"],
    "risk_level": "High",
    "malware_families": ["Cobalt Strike"]
  }
}
```

## Risk Assessment

The application calculates risk levels based on:

1. **CVSS Scores**: 
   - Critical: CVSS ≥ 9.0
   - High: CVSS ≥ 7.0
   - Medium: CVSS ≥ 4.0
   - Low: CVSS < 4.0

2. **Service Exposure**: 
   - 3+ exposed services increase risk by one level

3. **Threat Intelligence**:
   - Malware presence increases risk by one level
   - C2 indicators automatically set risk to Critical

4. **Special Cases**:
   - Cobalt Strike malware → Critical
   - Command & Control indicators → Critical

## AI Integration

### Supported AI Services
- **OpenAI GPT-4**: Primary AI service for generating summaries
- **Google Gemini**: Alternative AI service
- **Fallback**: Rule-based summary generation when AI services are unavailable

### Summary Format
AI-generated summaries include:
- Risk level and rationale
- Network information (ASN, organization)
- Exposed services with versions
- Critical vulnerabilities with CVSS scores
- Threat intelligence indicators
- Actionable security recommendations

## Development

### Project Structure
```
censys_exercise/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── requirements.txt     # Python dependencies
│   └── requirements-test.txt # Test dependencies
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── App.js           # Main application
│   │   ├── utils.js         # API utilities
│   │   └── constants.js     # Configuration constants
│   └── package.json         # Node.js dependencies
├── tests/                   # Centralized testing directory
│   ├── backend/             # Backend unit and integration tests
│   │   ├── test_main.py     # FastAPI application tests
│   │   └── pytest.ini       # Pytest configuration
│   ├── frontend/            # Frontend unit tests
│   │   ├── __tests__/       # React component and utility tests
│   │   ├── jest.config.js   # Jest configuration
│   │   └── setupTests.js    # Jest setup file
│   ├── e2e/                 # End-to-end tests
│   │   ├── tests/           # Playwright E2E test files
│   │   ├── playwright.config.js # Playwright configuration
│   │   └── package.json     # E2E test dependencies
│   ├── data/                # Test data and fixtures
│   │   ├── sample_hosts.json # Sample host data for testing
│   │   └── invalid.txt      # Invalid test files
│   ├── run-all-tests.sh     # Unix test runner
│   ├── run-all-tests.bat    # Windows test runner
│   └── README.md            # Testing documentation
├── scripts/                 # Setup and utility scripts
└── README.md                # This file
```

### Adding New Features

#### 1. Multi-file Dataset Support with Pagination

**Backend Implementation**:
- Add new endpoints in `main.py`:
  ```python
  @app.post("/upload_multiple_datasets/")
  async def upload_multiple_datasets(files: List[UploadFile]):
      """Upload and process multiple JSON dataset files."""
      # Implementation for handling multiple files
      # Store datasets with unique IDs and metadata
  
  @app.get("/get_datasets/")
  async def get_datasets(page: int = 1, limit: int = 10):
      """Get paginated list of uploaded datasets."""
      # Return paginated dataset metadata
  
  @app.get("/get_dataset/{dataset_id}/hosts/")
  async def get_dataset_hosts(dataset_id: str, page: int = 1, limit: int = 50):
      """Get paginated hosts from a specific dataset."""
      # Return paginated host data
  ```

- Add Pydantic models for pagination:
  ```python
  class PaginatedResponse(BaseModel):
      data: List[Any]
      total: int
      page: int
      limit: int
      total_pages: int
  ```

**Frontend Implementation**:
- Create `MultiFileUpload.js` component for drag-and-drop multiple file upload
- Add `DatasetList.js` component with pagination controls
- Implement `PaginationControls.js` reusable component
- Update `App.js` state to manage multiple datasets and pagination

#### 2. Enhanced Visualization Dashboards for Vulnerabilities and Risks

**Backend Implementation**:
- Add visualization data endpoints:
  ```python
  @app.get("/vulnerability_stats/")
  async def get_vulnerability_stats():
      """Get vulnerability statistics for dashboard."""
      # Aggregate CVE data, severity distribution, etc.
  
  @app.get("/risk_distribution/")
  async def get_risk_distribution():
      """Get risk level distribution across hosts."""
      # Calculate risk level percentages
  
  @app.get("/service_exposure_analysis/")
  async def get_service_exposure():
      """Get service exposure analysis."""
      # Most common services, ports, versions
  ```

**Frontend Implementation**:
- Install charting library: `npm install recharts`
- Create `VulnerabilityDashboard.js` with charts:
  - CVE severity pie chart
  - Risk level distribution bar chart
  - Service exposure heatmap
  - Timeline of vulnerabilities
- Add `RiskAnalysis.js` component with:
  - Risk trend over time
  - Geographic risk distribution
  - Top vulnerable services

#### 3. Caching Layer for Faster Repeated Summarization

**Backend Implementation**:
- Add Redis caching (install: `pip install redis`):
  ```python
  import redis
  import json
  from functools import wraps
  
  redis_client = redis.Redis(host='localhost', port=6379, db=0)
  
  def cache_result(expiry_seconds=3600):
      def decorator(func):
          @wraps(func)
          async def wrapper(*args, **kwargs):
              cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
              cached = redis_client.get(cache_key)
              if cached:
                  return json.loads(cached)
              result = await func(*args, **kwargs)
              redis_client.setex(cache_key, expiry_seconds, json.dumps(result))
              return result
          return wrapper
      return decorator
  
  @cache_result(expiry_seconds=1800)  # 30 minutes
  async def summarize_host(host_data):
      # Existing summarization logic
  ```

- Add cache management endpoints:
  ```python
  @app.delete("/clear_cache/")
  async def clear_cache():
      """Clear all cached summaries."""
      redis_client.flushdb()
      return {"message": "Cache cleared"}
  
  @app.get("/cache_stats/")
  async def get_cache_stats():
      """Get cache statistics."""
      return {
          "keys": redis_client.dbsize(),
          "memory_usage": redis_client.memory_usage()
      }
  ```

#### 4. Integration with External Threat Intelligence APIs

**Backend Implementation**:
- Add threat intelligence service:
  ```python
  class ThreatIntelligenceService:
      def __init__(self):
          self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
          self.shodan_api_key = os.getenv("SHODAN_API_KEY")
          self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
      
      async def check_ip_reputation(self, ip_address):
          """Check IP reputation across multiple sources."""
          results = {}
          # VirusTotal check
          # Shodan enrichment
          # AbuseIPDB reputation
          return results
      
      async def get_malware_indicators(self, ip_address):
          """Get malware indicators for IP."""
          # Check against known IOCs
          return indicators
  ```

- Add threat intelligence endpoints:
  ```python
  @app.get("/threat_intel/{ip_address}")
  async def get_threat_intelligence(ip_address: str):
      """Get threat intelligence for IP address."""
      ti_service = ThreatIntelligenceService()
      return await ti_service.check_ip_reputation(ip_address)
  
  @app.post("/enrich_hosts/")
  async def enrich_hosts_with_ti(hosts: List[str]):
      """Enrich multiple hosts with threat intelligence."""
      # Batch process threat intelligence lookup
  ```

**Frontend Implementation**:
- Create `ThreatIntelligencePanel.js` component
- Add threat intelligence indicators to host summaries
- Implement `ThreatScore.js` component for visual threat scoring

#### 5. User Authentication and Role-based Access Control

**Backend Implementation**:
- Add authentication dependencies:
  ```python
  pip install python-jose[cryptography] passlib[bcrypt] python-multipart
  ```

- Create authentication system:
  ```python
  from jose import JWTError, jwt
  from passlib.context import CryptContext
  from datetime import datetime, timedelta
  
  pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
  
  class UserManager:
      def create_user(self, username: str, password: str, role: str):
          # Create user with hashed password
      
      def authenticate_user(self, username: str, password: str):
          # Verify credentials
      
      def create_access_token(self, data: dict):
          # Generate JWT token
  
  @app.post("/auth/login")
  async def login(username: str, password: str):
      """Authenticate user and return JWT token."""
  
  @app.post("/auth/register")
  async def register(username: str, password: str, role: str = "user"):
      """Register new user."""
  ```

- Add role-based access control:
  ```python
  def require_role(required_role: str):
      def decorator(func):
          @wraps(func)
          async def wrapper(*args, **kwargs):
              # Check user role from JWT token
              # Allow/deny access based on role
          return wrapper
      return decorator
  
  @app.get("/admin/stats/")
  @require_role("admin")
  async def get_admin_stats():
      """Admin-only endpoint for system statistics."""
  ```

**Frontend Implementation**:
- Create authentication components:
  - `LoginForm.js`
  - `RegisterForm.js`
  - `ProtectedRoute.js`
  - `UserProfile.js`
- Add role-based UI rendering
- Implement JWT token management
- Add logout functionality

#### Testing for New Features

**Backend Tests**:
```python
# tests/backend/test_new_features.py
def test_multi_file_upload():
    """Test multiple file upload functionality."""
    
def test_pagination():
    """Test pagination for datasets and hosts."""
    
def test_caching():
    """Test caching layer functionality."""
    
def test_threat_intelligence():
    """Test threat intelligence API integration."""
    
def test_authentication():
    """Test user authentication and authorization."""
```

**Frontend Tests**:
```javascript
// frontend/src/__tests__/NewFeatures.test.js
describe('MultiFileUpload', () => {
  test('handles multiple file selection');
  test('shows upload progress');
});

describe('VulnerabilityDashboard', () => {
  test('renders charts correctly');
  test('updates on data change');
});
```

**E2E Tests**:
```javascript
// tests/e2e/tests/new-features.spec.js
test('complete multi-file workflow', async ({ page }) => {
  // Test full multi-file upload and analysis workflow
});

test('dashboard visualization', async ({ page }) => {
  // Test dashboard rendering and interactions
});
```

### Code Style
- **Backend**: Follow PEP 8 with type hints and docstrings
- **Frontend**: Use modern React patterns with hooks and functional components
- **Tests**: Comprehensive coverage with clear test names and descriptions

## Deployment

### Production Considerations
1. **Environment Variables**: Set production API keys and database URLs
2. **CORS**: Configure CORS for production domains
3. **File Size Limits**: Adjust upload limits based on requirements
4. **Rate Limiting**: Implement rate limiting for API endpoints
5. **Monitoring**: Add logging and monitoring for production use

### Docker Deployment
```dockerfile
# Backend Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# Frontend Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
CMD ["npm", "start"]
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request with a clear description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the API documentation at `/docs` when running the backend
2. Review the test files for usage examples
3. Check the browser console for frontend errors
4. Review backend logs for server-side issues
