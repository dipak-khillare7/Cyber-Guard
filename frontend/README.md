# AI-Based Cybersecurity Threat Detection & Response System — Frontend (SOC Dashboard)

A modern, responsive Security Operations Center (SOC) monitoring interface built with React, Vite, Recharts, and Lucide React. It provides real-time security overview, AI threat detection logs, alert management, incident case timelines, simulated response audit trails, and model architecture settings.

---

## 🛠 Tech Stack

- **Framework**: React 18 + Vite
- **Routing**: React Router DOM v6
- **Data Visualization**: Recharts (PieChart, BarChart, AreaChart)
- **Icons**: Lucide React
- **HTTP Client**: Axios (centralized API client with standard error handling)
- **Styling**: Vanilla CSS Modules / CSS Variables (Custom dark SOC theme with HSL colors & glassmorphism)

---

## 📁 Project Architecture

```text
frontend/
├── public/
│   └── favicon.ico
├── src/
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.jsx              # SOC Navigation sidebar
│   │   │   └── Topbar.jsx               # System status indicator, health polling, refresh button
│   │   ├── dashboard/
│   │   │   ├── SecurityOverview.jsx     # Overview KPI cards
│   │   │   ├── ThreatDistributionChart.jsx # Recharts Pie Chart for categories
│   │   │   ├── RiskSummaryChart.jsx     # Recharts Bar Chart for risk levels
│   │   │   └── DetectionTrendChart.jsx  # Recharts 24-Hour Area Chart
│   │   ├── detections/
│   │   │   ├── DetectionDetailsModal.jsx # Detailed event inspection & ML prediction breakdown
│   │   │   └── AnalyzeEventFormModal.jsx # Interactive custom event analyzer form
│   │   ├── alerts/
│   │   │   └── AlertDetailsModal.jsx    # Alert review & status update modal
│   │   ├── incidents/
│   │   │   └── IncidentDetailsModal.jsx  # Incident case file & 6-stage chronological timeline
│   │   ├── response/
│   │   │   └── ResponseDetailsModal.jsx # Safe audit log modal with simulation notice
│   │   └── common/
│   │       ├── LoadingState.jsx         # Loading spinner indicator
│   │       ├── ErrorState.jsx           # Error state with retry trigger
│   │       ├── EmptyState.jsx           # Empty state container
│   │       ├── RiskBadge.jsx            # Low/Medium/High/Critical color badges
│   │       ├── StatusBadge.jsx          # Status badges (New, Investigating, Resolved, etc.)
│   │       └── Pagination.jsx           # Page navigation controls
│   ├── pages/
│   │   ├── Dashboard.jsx                # Main SOC Monitoring Dashboard
│   │   ├── Detections.jsx               # Paginated AI Threat Detection History
│   │   ├── Alerts.jsx                   # Alert Management & Triage
│   │   ├── Incidents.jsx                # Incident Case Management & Timeline
│   │   ├── ResponseActions.jsx          # Simulated Response Action Audit Log
│   │   └── Settings.jsx                 # System Health & ML Model Metadata
│   ├── services/
│   │   ├── api.js                       # Central Axios instance
│   │   ├── detectionService.js          # Detection API calls
│   │   ├── alertService.js              # Alert API calls
│   │   ├── incidentService.js          # Incident API calls
│   │   ├── statisticsService.js        # Statistics API calls
│   │   └── responseService.js          # Response action API calls
│   ├── hooks/
│   │   ├── useStatistics.js             # Statistics polling & state hook
│   │   ├── useDetections.js             # Detections query hook
│   │   ├── useAlerts.js                 # Alerts query hook
│   │   └── useIncidents.js              # Incidents query hook
│   ├── utils/
│   │   ├── constants.js                 # App configuration & color palettes
│   │   ├── formatDate.js                # ISO date formatting helper
│   │   ├── formatRisk.js                # Risk badge & score formatter
│   │   └── formatThreat.js              # Dynamic threat label formatter
│   ├── App.jsx                          # Main App component & router configuration
│   ├── main.jsx                         # React entry point
│   └── index.css                        # Design system & dark SOC stylesheet
├── .env.example
├── package.json
└── README.md
```

---

## ⚡ Environment Variables

Create a `.env` file in `frontend/` based on `.env.example`:

```env
VITE_API_BASE_URL=http://localhost:8000
```

---

## 🚀 Development & Build Commands

### Install Dependencies
```bash
npm install
```

### Start Development Server
```bash
npm run dev
```
The application will launch on `http://localhost:5173`.

### Production Build
```bash
npm run build
```

### Preview Production Build
```bash
npm run preview
```

---

## 🛡️ Security & Integrity Principles

1. **Real Data Consumption**: All statistics, threat charts, risk levels, and alerts are fetched directly from the FastAPI backend database endpoints.
2. **Safe Response Simulation**: Automated response actions (`SIMULATED_BLOCK`, `SIMULATED_ISOLATION`) are explicitly labeled as simulation-only with no execution of disruptive network scripts.
3. **Zero Frontend Credentials**: Database passwords and private backend keys are never included in client-side code.
