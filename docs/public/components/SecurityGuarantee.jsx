export function SecurityGuarantee({ establishes = [], doesNotEstablish = [] }) {
  return (
    <div className="security-guarantee" role="group" aria-label="Security guarantee">
      <section>
        <h3>This establishes</h3>
        <ul>
          {establishes.map((item) => <li key={item}>✓ {item}</li>)}
        </ul>
      </section>
      <section>
        <h3>This does not establish</h3>
        <ul>
          {doesNotEstablish.map((item) => <li key={item}>– {item}</li>)}
        </ul>
      </section>
    </div>
  );
}
