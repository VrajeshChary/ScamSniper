function checkScam() {
  const input = document.getElementById("linkInput").value.trim();
  const result = document.getElementById("result");

  if (input === "") {
    result.innerHTML = "⚠️ Please enter a link to check.";
    return;
  }

  fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: input })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      result.innerHTML = `<p style="color: red;">❌ ${data.error}</p>`;
      return;
    }

    result.innerHTML = `
      <h3>📋 Scan Report for: <span style="color:#007cf0">${input}</span></h3>
      <ul>
        <li><strong>IP:</strong> ${data.ip}</li>
        <li><strong>Location:</strong> ${data.city}, ${data.country}</li>
        <li><strong>ISP:</strong> ${data.org}</li>
        <li><strong>Abuse Score:</strong> <span style="color:red">${data.abuse_score}/100</span></li>
        <li><strong>VirusTotal Detections:</strong> ${data.malicious} malicious, ${data.suspicious} suspicious</li>
      </ul>
      <p style="color: #555;">🚨 Use caution when visiting this site.</p>
    `;
  });
}