function SharedHeader() {
  return (
    <header className="shared-mountain-header">

      <div className="shared-header-brand">

        <img
          src={`${import.meta.env.BASE_URL}threatmodel-symbol.png`}
          alt="ThreatModel AI"
        />

        <div>
          <div className="shared-header-title">
            ThreatModel <span>AI</span>
          </div>

          <div className="shared-header-tagline">
            MODEL <b>•</b>
            ANALYZE <b>•</b>
            SECURE <b>•</b>
            CONTINUOUSLY
          </div>
        </div>

      </div>

    </header>
  );
}

export default SharedHeader;
