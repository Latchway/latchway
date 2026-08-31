function boundedNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function QuotaPreview() {
  const [requests, setRequests] = React.useState(1);
  const [input, setInput] = React.useState(500);
  const [outputMaximum, setOutputMaximum] = React.useState(1000);
  const [actualOutput, setActualOutput] = React.useState(250);
  const [pricePerMillion, setPricePerMillion] = React.useState(2);
  const [userLimit, setUserLimit] = React.useState(5000);
  const [featureLimit, setFeatureLimit] = React.useState(10000);
  const [applicationBudget, setApplicationBudget] = React.useState(0.05);
  const result = React.useMemo(() => {
    const count = boundedNumber(requests, 0);
    const reserved = count * (boundedNumber(input, 0) + boundedNumber(outputMaximum, 0));
    const actual = count * (boundedNumber(input, 0) + Math.min(boundedNumber(actualOutput, 0), boundedNumber(outputMaximum, 0)));
    const reservedCost = reserved * boundedNumber(pricePerMillion, 0) / 1000000;
    const settledCost = actual * boundedNumber(pricePerMillion, 0) / 1000000;
    const deniedBy = [];
    if (reserved > boundedNumber(userLimit, 0)) deniedBy.push("user token limit");
    if (reserved > boundedNumber(featureLimit, 0)) deniedBy.push("feature token limit");
    if (reservedCost > boundedNumber(applicationBudget, 0)) deniedBy.push("application cost budget");
    return {
      reserved,
      actual,
      reservedCost,
      settledCost,
      userRemaining: Math.max(0, boundedNumber(userLimit, 0) - actual),
      featureRemaining: Math.max(0, boundedNumber(featureLimit, 0) - actual),
      budgetRemaining: Math.max(0, boundedNumber(applicationBudget, 0) - settledCost),
      deniedBy,
    };
  }, [requests, input, outputMaximum, actualOutput, pricePerMillion, userLimit, featureLimit, applicationBudget]);
  return (
    <section aria-labelledby="quota-preview-title">
      <h2 id="quota-preview-title">Preview reserve, execute, and settle</h2>
      <p>This teaching calculator uses one illustrative token price. The gateway remains authoritative for model-aware tokenization, distinct input/output prices, policy windows, and trusted settlement.</p>
      <label>Requests <input type="number" min="0" value={requests} onChange={(event) => setRequests(event.target.value)} /></label>
      <label>Input tokens per request <input type="number" min="0" value={input} onChange={(event) => setInput(event.target.value)} /></label>
      <label>Output maximum per request <input type="number" min="0" value={outputMaximum} onChange={(event) => setOutputMaximum(event.target.value)} /></label>
      <label>Actual output per request <input type="number" min="0" value={actualOutput} onChange={(event) => setActualOutput(event.target.value)} /></label>
      <label>Illustrative USD per million tokens <input type="number" min="0" step="0.01" value={pricePerMillion} onChange={(event) => setPricePerMillion(event.target.value)} /></label>
      <label>User token limit <input type="number" min="0" value={userLimit} onChange={(event) => setUserLimit(event.target.value)} /></label>
      <label>Feature token limit <input type="number" min="0" value={featureLimit} onChange={(event) => setFeatureLimit(event.target.value)} /></label>
      <label>Application cost budget in USD <input type="number" min="0" step="0.01" value={applicationBudget} onChange={(event) => setApplicationBudget(event.target.value)} /></label>
      <dl aria-live="polite">
        <div><dt>Reserved maximum</dt><dd>{result.reserved} tokens (${result.reservedCost.toFixed(6)})</dd></div>
        <div><dt>Actual settlement</dt><dd>{result.actual} tokens (${result.settledCost.toFixed(6)})</dd></div>
        <div><dt>Remaining user allowance</dt><dd>{result.userRemaining} tokens</dd></div>
        <div><dt>Remaining feature allowance</dt><dd>{result.featureRemaining} tokens</dd></div>
        <div><dt>Remaining application budget</dt><dd>${result.budgetRemaining.toFixed(6)}</dd></div>
        <div><dt>Pre-dispatch decision</dt><dd>{result.deniedBy.length ? `Denied by ${result.deniedBy.join(", ")}` : "All illustrative reservations can proceed"}</dd></div>
      </dl>
    </section>
  );
}
