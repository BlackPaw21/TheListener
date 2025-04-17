#!/usr/bin/env python3
from flask import Flask, render_template_string, abort, url_for, request
import os, re, json

app = Flask(__name__)
LOG_DIR = "logs"

# Define keywords for classification.
AD_KEYWORDS = ["ad", "syndication", "doubleclick", "ads-router", "pagead2"]
SERVICE_KEYWORDS = ["gstatic", "ytig", "cvtapi"]

def classify_entry(entry):
    """
    Classify a log entry based on its URL:
      - If the URL contains any service keywords, return "Service".
      - If the URL contains any ad keywords, return "Ad/Service".
      - Otherwise, if a URL is found, return "Website".
      - If no URL is found, return "Other".
    """
    url_match = re.search(r'(https?://\S+)', entry)
    if url_match:
        url = url_match.group(1).lower()
        # Check for service keywords first.
        for keyword in SERVICE_KEYWORDS:
            if keyword in url:
                return "Service"
        # Then check for ad-related keywords.
        for keyword in AD_KEYWORDS:
            if keyword in url:
                return "Ad/Service"
        return "Website"
    return "Other"

# --- Templates ---

INDEX_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Bettercap Log Viewer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Arial, sans-serif; background: #f8f9fa; margin: 20px; }
    .container { max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { color: #343a40; }
    ul { list-style: none; padding: 0; }
    li { margin: 8px 0; }
    a { text-decoration: none; color: #007bff; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Bettercap Log Viewer</h1>
    <h3>Available Log Files:</h3>
    {% if files %}
      <ul>
      {% for file in files %}
        <li><a href="{{ url_for('view_log', filename=file) }}">{{ file }}</a></li>
      {% endfor %}
      </ul>
    {% else %}
      <p>No logs found.</p>
    {% endif %}
  </div>
</body>
</html>
"""

LOG_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Log Viewer - {{ filename }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Include Chart.js from CDN -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; background: #f8f9fa; margin: 20px; }
    .container { max-width: 1000px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { color: #343a40; }
    .tabs { overflow: hidden; border-bottom: 1px solid #ccc; }
    .tabs button { background: none; border: none; outline: none; padding: 14px 16px; cursor: pointer; font-size: 17px; }
    .tabs button:hover { background-color: #ddd; }
    .tabs button.active { background-color: #ccc; }
    .tabcontent { display: none; padding: 20px 0; }
    #searchInput { width: 100%; padding: 8px; margin-bottom: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
    th { background-color: #f2f2f2; }
    canvas { max-width: 100%; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Log Viewer - {{ filename }}</h1>
    <p><a href="{{ url_for('index') }}">Back to log list</a></p>
    <div class="tabs">
      <button class="tablinks" onclick="openTab(event, 'EntireLog')" id="defaultOpen">Entire Log</button>
      <button class="tablinks" onclick="openTab(event, 'TopURLs')">Top Visited URLs</button>
      <button class="tablinks" onclick="openTab(event, 'Credentials')">Detected Credentials</button>
    </div>

    <!-- Tab 1: Entire Log -->
    <div id="EntireLog" class="tabcontent">
      <input type="text" id="searchInput" placeholder="Search logs..." onkeyup="filterTable()">
      <table id="logTable">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Message</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody>
          {% for entry in entries %}
          <tr>
            <td>{{ entry.timestamp }}</td>
            <td>{{ entry.message }}</td>
            <td>{{ entry.type }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Tab 2: Top Visited URLs -->
    <div id="TopURLs" class="tabcontent">
      <canvas id="urlChart" style="height:400px;"></canvas>
    </div>

    <!-- Tab 3: Detected Credentials -->
    <div id="Credentials" class="tabcontent">
      <table id="credTable">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Credential Log</th>
          </tr>
        </thead>
        <tbody>
          {% for entry in entries if entry.type == "Ad/Service" or entry.type == "Service" %}
          <tr>
            <td>{{ entry.timestamp }}</td>
            <td>{{ entry.message }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    function openTab(evt, tabName) {
      var i, tabcontent, tablinks;
      tabcontent = document.getElementsByClassName("tabcontent");
      for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
      }
      tablinks = document.getElementsByClassName("tablinks");
      for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
      }
      document.getElementById(tabName).style.display = "block";
      evt.currentTarget.className += " active";
      if (tabName === "TopURLs") {
        renderChart();
      }
    }
    document.getElementById("defaultOpen").click();

    function filterTable() {
      var input, filter, table, tr, td, i, j, txtValue;
      input = document.getElementById("searchInput");
      filter = input.value.toLowerCase();
      table = document.getElementById("logTable");
      tr = table.getElementsByTagName("tr");
      for (i = 1; i < tr.length; i++) {
        tr[i].style.display = "none";
        td = tr[i].getElementsByTagName("td");
        for (j = 0; j < td.length; j++) {
          if (td[j]) {
            txtValue = td[j].textContent || td[j].innerText;
            if (txtValue.toLowerCase().indexOf(filter) > -1) {
              tr[i].style.display = "";
              break;
            }
          }
        }
      }
    }

    function getURLData() {
      var entries = {{ entries|tojson }};
      var urlRegex = /(https?:\/\/\S+)/gi;
      var counts = {};
      for (var i = 0; i < entries.length; i++) {
        var msg = entries[i].message;
        var matches = msg.match(urlRegex);
        if (matches) {
          matches.forEach(function(url) {
            url = url.replace(/[,\)\]\}]+$/, "");
            counts[url] = (counts[url] || 0) + 1;
          });
        }
      }
      var data = [];
      for (var url in counts) {
        data.push({url: url, count: counts[url]});
      }
      data.sort(function(a, b) {
        return b.count - a.count;
      });
      return data.slice(0, 10);
    }

    function renderChart() {
      var data = getURLData();
      var labels = data.map(function(item) { return item.url; });
      var counts = data.map(function(item) { return item.count; });
      var ctx = document.getElementById('urlChart').getContext('2d');
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'URL Hits',
            data: counts,
            backgroundColor: 'rgba(0, 123, 255, 0.6)',
            borderColor: 'rgba(0, 123, 255, 1)',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { 
              ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 }
            },
            y: { beginAtZero: true }
          }
        }
      });
    }
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    if not os.path.exists(LOG_DIR):
        return "<h1>No logs found.</h1>"
    files = sorted([f for f in os.listdir(LOG_DIR) if f.startswith("bettercap_log_") and f.endswith(".txt")], reverse=True)
    return render_template_string(INDEX_TEMPLATE, files=files)

@app.route("/log/<path:filename>")
def view_log(filename):
    if ".." in filename or filename.startswith("/"):
        abort(404)
    filepath = os.path.join(LOG_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    with open(filepath, "r") as f:
        lines = f.readlines()
    entries = []
    for line in lines:
        line = line.strip()
        if line.startswith("[") and "]" in line:
            timestamp, message = line.split("]", 1)
            timestamp += "]"
            message = message.strip()
            entry_type = classify_entry(message)
            entries.append({"timestamp": timestamp, "message": message, "type": entry_type})
        else:
            entries.append({"timestamp": "", "message": line, "type": "Other"})
    return render_template_string(LOG_TEMPLATE, filename=filename, entries=entries)

def classify_entry(entry):
    """
    Classify a log entry based on its URL:
      - If the URL contains any service keywords, return "Service".
      - If the URL contains any ad keywords, return "Ad/Service".
      - Otherwise, if a URL is found, return "Website".
      - If no URL is found, return "Other".
    """
    url_match = re.search(r'(https?://\S+)', entry)
    if url_match:
        url = url_match.group(1).lower()
        for kw in SERVICE_KEYWORDS:
            if kw in url:
                return "Service"
        for kw in AD_KEYWORDS:
            if kw in url:
                return "Ad/Service"
        return "Website"
    return "Other"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
