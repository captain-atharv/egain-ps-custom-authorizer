const processor = require('./processor');

exports.handler = async (event) => {
  const results = await processor.authorizeEvent(event);
  results.usageIdentifierKey = process.env.UsagePlanAPIKey;
  return results;
};
