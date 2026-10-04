import React from 'react';
import {
  Info, Shield, AlertTriangle, Code2, Brain,
  GitBranch, Zap, Lock, ChevronRight,
} from 'lucide-react';
import Header from '../components/Header';

const techStack = [
  { label: 'React 18', category: 'Frontend' },
  { label: 'Vite', category: 'Frontend' },
  { label: 'Recharts', category: 'Frontend' },
  { label: 'Lucide React', category: 'Frontend' },
  { label: 'Axios', category: 'Frontend' },
  { label: 'Python 3.11+', category: 'Backend' },
  { label: 'FastAPI', category: 'Backend' },
  { label: 'Uvicorn', category: 'Backend' },
  { label: 'Pydantic', category: 'Backend' },
  { label: 'Scikit-learn', category: 'ML' },
  { label: 'Pandas', category: 'ML' },
  { label: 'NumPy', category: 'ML' },
  { label: 'Joblib', category: 'ML' },
  { label: 'Logistic Regression', category: 'Algorithm' },
  { label: 'Decision Tree', category: 'Algorithm' },
  { label: 'Random Forest', category: 'Algorithm' },
];

const mlWorkflow = [
  { title: 'Dataset Loading', desc: 'Load phishing & legitimate URL dataset with binary labels (0=legitimate, 1=phishing).' },
  { title: 'Data Cleaning', desc: 'Remove null values, validate label encoding, ensure URL strings are non-empty.' },
  { title: 'Feature Extraction', desc: 'Extract 19 structural URL features (length, dots, hyphens, keywords, IP detection, etc.) without visiting any URL.' },
  { title: 'Train/Test Split', desc: 'Stratified 80/20 split preserving class ratios for unbiased evaluation.' },
  { title: 'Model Training', desc: 'Train Logistic Regression, Decision Tree, and Random Forest on the feature matrix.' },
  { title: 'Evaluation', desc: 'Compute Accuracy, Precision, Recall, F1-score, and Confusion Matrix for each model.' },
  { title: 'Model Selection', desc: 'Select the best model based on F1-score with priority on phishing recall.' },
  { title: 'Persistence', desc: 'Save the selected model and metrics using Joblib for use by the FastAPI inference API.' },
];

const limitations = [
  'URL-only analysis — page content, certificates, and WHOIS are not inspected.',
  'Cannot detect phishing sites with legitimate-looking URLs.',
  'Training data size affects generalization — more data improves accuracy.',
  'Not a substitute for professional threat intelligence or browser security warnings.',
  'Adversarial URLs specifically crafted to evade URL-based analysis may bypass detection.',
  'Model must be periodically retrained as phishing techniques evolve.',
];

const futureWork = [
  'Integration with VirusTotal or OpenPhish blocklists (non-paid tiers)',
  'Browser extension for real-time URL analysis',
  'Domain age and WHOIS data features',
  'Deep learning models (LSTM/BERT) for URL sequence analysis',
  'Continuous retraining pipeline with fresh phishing URL feeds',
  'Certificate transparency log integration',
];

export default function About() {
  return (
    <div className="page-container animate-fade-in">
      <Header
        title="About PhishGuard AI"
        subtitle="AI-Powered Phishing Website Detection System"
        icon={Info}
      />

      {/* Overview */}
      <div className="about-section">
        <div className="about-section-title">
          <Shield size={18} color="var(--color-green)" />
          Project Overview
        </div>
        <p style={{ lineHeight: 1.8, marginBottom: 12 }}>
          <strong style={{ color: 'var(--text-primary)' }}>PhishGuard AI</strong> is an
          AI/ML-powered phishing website detection system that analyzes URL structure to
          predict whether a URL is likely to be a phishing attempt or a legitimate website.
        </p>
        <p style={{ lineHeight: 1.8, marginBottom: 12 }}>
          The system uses three machine learning classifiers trained on a labeled dataset of
          legitimate and phishing URL patterns. Features are extracted purely from the URL
          string — the target website is <em>never</em> visited, crawled, or executed.
        </p>
        <p style={{ lineHeight: 1.8 }}>
          This project demonstrates a complete ML pipeline from data preprocessing and
          feature engineering to model evaluation, API deployment, and a production-style
          React frontend.
        </p>
      </div>

      {/* Problem Statement */}
      <div className="about-section">
        <div className="about-section-title">
          <AlertTriangle size={18} color="var(--color-amber)" />
          Problem Statement
        </div>
        <p style={{ lineHeight: 1.8 }}>
          Phishing attacks remain one of the most prevalent cybersecurity threats. Attackers
          craft deceptive URLs that mimic legitimate services to steal credentials and
          financial information. Traditional blocklist-based detection is reactive and cannot
          identify new phishing sites. Machine learning-based URL analysis provides a
          proactive approach by detecting structural patterns common in phishing URLs.
        </p>
      </div>

      {/* ML Workflow */}
      <div className="about-section">
        <div className="about-section-title">
          <Brain size={18} color="var(--color-blue)" />
          Machine Learning Workflow
        </div>
        <div className="workflow-steps">
          {mlWorkflow.map((step, i) => (
            <div className="workflow-step" key={i}>
              <div className="step-number">{i + 1}</div>
              <div className="step-content">
                <div className="step-title">{step.title}</div>
                <div className="step-desc">{step.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technology Stack */}
      <div className="about-section">
        <div className="about-section-title">
          <Code2 size={18} color="var(--color-purple)" />
          Technology Stack
        </div>
        <div className="tech-grid">
          {techStack.map((t) => (
            <div key={t.label} className="tech-chip">
              <ChevronRight size={12} />
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  {t.label}
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  {t.category}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Limitations */}
      <div className="about-section">
        <div className="about-section-title">
          <AlertTriangle size={18} color="var(--color-red)" />
          Known Limitations
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {limitations.map((l, i) => (
            <div key={i} className="indicator-item warning" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              <AlertTriangle size={13} color="var(--color-amber)" />
              {l}
            </div>
          ))}
        </div>
      </div>

      {/* Future Enhancements */}
      <div className="about-section">
        <div className="about-section-title">
          <Zap size={18} color="var(--color-cyan)" />
          Future Enhancements
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {futureWork.map((f, i) => (
            <div key={i} className="indicator-item positive">
              <ChevronRight size={13} />
              {f}
            </div>
          ))}
        </div>
      </div>

      {/* Security */}
      <div className="about-section">
        <div className="about-section-title">
          <Lock size={18} color="var(--color-green)" />
          Security Considerations
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            'The system never visits, fetches, or executes submitted URLs.',
            'Only the URL string and its structural components are analyzed.',
            'No credentials, cookies, or authentication tokens are stored.',
            'History is stored in server memory only and cleared on restart.',
            'Input validation prevents malformed URL injection attacks.',
            'CORS is configured to allow only the localhost frontend origin.',
          ].map((s, i) => (
            <div key={i} className="indicator-item positive">
              <Shield size={13} />
              {s}
            </div>
          ))}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="disclaimer-box">
        <div className="disclaimer-title">
          <AlertTriangle size={16} />
          Disclaimer
        </div>
        <p className="disclaimer-text">
          This system provides an ML-based risk assessment and is <strong>not a substitute</strong> for
          professional security tools or threat intelligence. Confidence scores and risk assessments
          are model estimates and may not reflect the true nature of a website. Always verify
          suspicious URLs through multiple security sources before trusting or visiting them.
          The model cannot guarantee that any URL is safe.
        </p>
      </div>
    </div>
  );
}
