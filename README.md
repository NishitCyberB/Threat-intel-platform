# Threat Intelligence Platform (TIP) + Dynamic Policy Enforcer

**Project 1 – Finance & Banking (Infotact Internship)**

Advanced Threat Intelligence Platform that collects OSINT feeds, stores IOCs in MongoDB, syncs to Elasticsearch (SIEM), visualizes in Kibana, and automatically enforces firewall rules.

## Features
- Collection from 3 public OSINT feeds (URLHaus, OpenPhish, AlienVault OTX)
- Risk scoring system
- MongoDB + Elasticsearch (ELK Stack) integration
- Real-time Kibana dashboard
- Dynamic firewall policy enforcement (iptables)
- Rollback UI for false positives
- Fully Dockerized (MongoDB + Flask + ELK)

## Tech Stack
- **Backend**: Python + Flask + Gunicorn
- **Database**: MongoDB
- **SIEM**: Elasticsearch + Kibana
- **Containerization**: Docker + Docker Compose
- **Firewall**: Linux iptables

## Architecture Diagram

```mermaid
graph TD
    A[OSINT Feeds<br>(URLHaus + OpenPhish + AlienVault OTX)] --> B[Threat Collector + Risk Scoring]
    B --> C[MongoDB<br>(IOC Storage)]
    C --> D[Sync Script<br>(sync_to_es.py)]
    D --> E[Elasticsearch<br>(SIEM)]
    E --> F[Kibana Dashboard]
    C --> G[Dynamic Policy Enforcer]
    G --> H[Linux iptables Firewall]
    F --> I[Rollback UI]
    I --> G

## Quick Start

```bash
# Clone repo
git clone https://github.com/NishitCyberB/Threat-intel-platform.git
cd Threat-intel-platform

# Start all services
sudo docker-compose -f docker-compose.yml -f docker-compose.elk.yml up -d
