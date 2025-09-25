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

1. **Backend**: Add new endpoints in `main.py` with proper validation and error handling
2. **Frontend**: Create new components in `src/components/` and update `App.js`
3. **Tests**: Add corresponding tests in the `tests/` directory structure
4. **Documentation**: Update this README with new features and API changes

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
