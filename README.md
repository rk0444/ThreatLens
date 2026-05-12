# ThreatLens

A unified cybersecurity platform that simultaneously monitors the entire internet for known threats and watches your machines for active attacks - using the same AI brain to rank, explain and respond to everything in one place. Covers the world and your laptop at the same time. ONE DASHBOARD. ONE PRIORITY QUEUE. ONE AI.

## 🚀 Features

- **Real-time Threat Intelligence**: Monitors global threat feeds including CVE databases, OSINT alerts, and IP reputation data
- **Local Attack Detection**: Watches your machines for active security breaches and suspicious activities
- **AI-Powered Analysis**: Uses advanced AI to rank, explain, and prioritize threats automatically
- **Unified Dashboard**: Single interface for both global and local security monitoring
- **Real-time Updates**: WebSocket-based live threat updates and notifications
- **Cross-Platform**: Available as both web application and desktop app (Electron)

## 🏗️ Architecture

- **Frontend**: React + Vite with modern UI components (Recharts, D3.js, Framer Motion)
- **Backend**: FastAPI with SQLAlchemy for database management
- **Desktop App**: Electron wrapper for cross-platform desktop deployment
- **Database**: SQLite with SQLAlchemy ORM
- **Real-time Communication**: WebSocket support for live updates

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

2. **Install dependencies**
   ```bash
   # Install root dependencies
   npm install
   
   # Install frontend dependencies
   cd frontend && npm install && cd ..
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

4. **Run the development server**
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
├── backend/            # FastAPI backend application
│   ├── database/      # Database models and schemas
│   ├── services/      # External API integrations
│   └── main.py        # Main FastAPI application
├── frontend/          # React frontend application
│   ├── src/          # React components and pages
│   └── public/       # Static assets
├── build/            # Electron build outputs
├── docker-compose.yml # Docker deployment configuration
├── main.js           # Electron main process
└── package.json      # Root package configuration
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
