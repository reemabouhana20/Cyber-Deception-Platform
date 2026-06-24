# Intelligent Multi-Service Honeypot & AI-Powered Threat Detection Platform

## Project Overview
An advanced cybersecurity platform designed to emulate multiple network services (SSH, FTP, Telnet, HTTP, MySQL, RDP) using a distributed honeypot architecture. The system leverages Machine Learning (XGBoost, CNN, LSTM) to perform real-time threat classification, predictive attack modeling, and automated incident response, all mapped to the MITRE ATT&CK framework.

## System Highlights
* Multi-Service Deception: Deployed a hybrid architecture using Cowrie (SSH) and OpenCanary (diverse services) to broaden the attack surface.
* AI-Driven Data Synthesis: Used Gemma AI to generate smart, adaptive attack scenarios to ensure model robustness and better training datasets.
* Predictive Analytics: Implemented a multi-model approach:
    * XGBoost (99.5% Accuracy): Used for lightning-fast real-time attack/normal classification.
    * CNN (95.3% Accuracy): Optimized for behavioral session classification.
    * LSTM: Utilized for temporal threat trend prediction.
* Strategic Mapping: Automated mapping of detected attacker behaviors to MITRE ATT&CK techniques (e.g., T1033, T1053, T1070).
* Automated Alerting: Real-time Telegram bot integration for instant notification of high-risk persistent threats.

## Architecture & Data Flow
The system utilizes a distributed approach across four VMs to ensure isolated and efficient data processing:
1. Honeypot Layer: Cowrie (SSH) & OpenCanary.
2. Data Pipeline: Filebeat & ELK Stack for centralized logging.
3. Intelligence Layer: AI models processing data to detect anomalies.
4. Attacker VM: Kali Linux environments for generating controlled attack traffic.

## Model Performance
| Model | Accuracy | Best Use Case |
| :--- | :--- | :--- |
| XGBoost | 99.5% | Real-time classification |
| CNN 1D | 95.3% | Behavioral session classification |
| LSTM | 74.8% | Sequential temporal prediction |

## Getting Started
1. Infrastructure Setup: Initialize ELK, Cowrie, and OpenCanary services.
2. Data Generation: Execute `gemma_attacker.py` for smart attacks and `normal_traffic.py` for baseline behavior.
3. Analysis: Run `live_xgboost.py` or `live_cnn.py` for real-time threat detection.
4. Visualization: Access the Streamlit Dashboard at `http://localhost:8501` to view MITRE mapping and live alerts.

## Future Roadmap
* Expanding honeypot coverage with Dionaea (Malware analysis).
* Enhancing Zero-Day detection capabilities using Isolation Forest algorithms.

---
*Developed as a graduation project to advance automated threat detection and incident response mechanisms.*
