const convertObjectKeysToLower = (object) => {
  const keys = Object.keys(object);
  const lowerObj = {};
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    const modKey = key.toLowerCase();
    lowerObj[modKey] = object[key];
  }
  return lowerObj;
};

module.exports = { convertObjectKeysToLower };
