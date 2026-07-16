// EA050 (not yet implemented): remote response data flows into a shell
// command with no validation. This also happens to exercise EA020 today,
// since `info.installerPath` is a MemberExpression interpolated into a
// template literal — not one of the safe shapes isStaticSafeLiteral folds.
const { exec } = require('child_process');
const https = require('https');

function checkForUpdates() {
  https.get('https://example.com/update-info.json', (res) => {
    let body = '';
    res.on('data', (chunk) => {
      body += chunk;
    });
    res.on('end', () => {
      const info = JSON.parse(body);
      exec(`./run-installer.sh ${info.installerPath}`);
    });
  });
}

module.exports = { checkForUpdates };
