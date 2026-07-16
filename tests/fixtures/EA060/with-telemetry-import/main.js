const ReactGA = require('react-ga4');
const Sentry = require('@sentry/electron');

ReactGA.initialize('G-XXXX');
Sentry.init({ dsn: 'https://example' });
