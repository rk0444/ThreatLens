# ThreatLens

A unified cybersecurity platform that simultaneously monitors the entire internet for known threats and watches your machines for active attacks - using the same AI brain to rank, explain and respond to everything in one place. Covers the world and your laptop at the same time. ONE DASHBOARD. ONE PRIORITY QUEUE. ONE AI.

## 🚀 Features

- **Real-time Threat Intelligence**: Monitors global threat feeds including CVE databases, OSINT alerts, and IP reputation data
- **Local Attack Detection**: Watches your machines for active security breaches and suspicious activities
- **AI-Powered Analysis**: Uses advanced AI (LangChain, OpenAI, Groq) to rank, explain, and prioritize threats automatically
- **Vector Database**: ChromaDB integration for intelligent threat similarity search and context retrieval
- **Unified Dashboard**: Single interface for both global and local security monitoring
- **Real-time Updates**: WebSocket-based live threat updates and notifications
- **Cross-Platform**: Available as both web application and desktop app (Electron)
- **Security Agents**: Network monitoring, process monitoring, and automated response capabilities

## 🏗️ Architecture

- **Frontend**: React 19 + Vite with modern UI components (Recharts, D3.js, Framer Motion, Lucide React)
- **Backend**: FastAPI with SQLAlchemy for database management
- **AI/ML Stack**: LangChain, OpenAI, Groq, ChromaDB for intelligent threat analysis
- **Desktop App**: Electron wrapper for cross-platform desktop deployment
- **Database**: SQLite with SQLAlchemy ORM + ChromaDB vector database
- **Real-time Communication**: WebSocket support for live updates
- **Security Agents**: Network monitor, process monitor, sandbox, and automated responder

## 📦 Installation

### Prerequisites

- Node.js (v18 or higher)
- Python (v3.9 or higher)
- npm or yarn

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ThreatLens
   ```

2. **Set up Python virtual environment**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/Mac
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   # Install Python backend dependencies
   pip install -r backend/requirements.txt
   
   # Install root Node.js dependencies
   npm install
   
   # Install frontend dependencies
   cd frontend && npm install && cd ..
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

5. **Run the development server**
   ```bash
   npm run dev
   ```

This will start:
- Frontend development server at `http://localhost:5173`
- Backend API server at `http://localhost:8000`
- Electron desktop app

### Docker Deployment

```bash
docker-compose up -d
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL=sqlite:///./backend/database/threatlens.sqlite

# API Keys (optional for enhanced features)
NVD_API_KEY=your_nvd_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# AI/ML Configuration
OPENAI_API_KEY=your_openai_api_key_here
GROQ_API_KEY=your_groq_api_key_here

# AI Model Configuration
GROQ_MODEL=llama-3-70b-8192
OPENAI_MODEL=gpt-4o

# Vector Store Configuration
CHROMA_PERSIST_DIRECTORY=./backend/database/chroma
CHROMA_COLLECTION_THREATS=threat_intelligence
CHROMA_COLLECTION_INCIDENTS=incidents

# Application Settings
DEBUG=true
LOG_LEVEL=INFO
```

## 📚 API Documentation

Once the backend is running, visit `http://localhost:8000/docs` for interactive API documentation.

## 🖥️ Usage

1. **Dashboard View**: Monitor real-time threats and security events
2. **Threat Intelligence**: Browse CVE data, OSINT alerts, and IP reputation
3. **Local Monitoring**: View system security status and active attacks
4. **AI Analysis**: Get automated threat prioritization and explanations

## 📁 Project Structure

```
ThreatLens/
├── agent/              # Security monitoring agents
│   ├── network_monitor.py   # Network traffic monitoring
│   ├── process_monitor.py   # Process activity monitoring
│   ├── responder.py          # Automated threat response
│   └── sandbox.py           # Isolated execution environment
├── backend/            # FastAPI backend application
│   ├── database/      # Database models and schemas
│   ├── services/      # External API integrations
│   ├── main.py        # Main FastAPI application
│   └── requirements.txt # Python dependencies
├── frontend/          # React frontend application
│   ├── src/          # React components and pages
│   ├── public/       # Static assets
│   └── package.json  # Frontend dependencies
├── build/            # Electron build outputs
├── docker-compose.yml # Docker deployment configuration
├── main.js           # Electron main process
├── package.json      # Root package configuration
└── .env.example      # Environment variables template
```

## 🛠️ Development

### Running Tests

```bash
# Test all APIs
python test_all_apis.py

# Test specific endpoints
python test_single_endpoint.py

# Test lifespan functionality
python test_lifespan.py
```

### Building for Production

```bash
npm run build
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Check the [API Health Report](API_HEALTH_REPORT.md) for system status
- Review the application logs for debugging information
- Open an issue in the repository

---

**ThreatLens v2.0.0** - Unified Cybersecurity Platform
