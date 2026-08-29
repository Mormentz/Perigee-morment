import React, { useMemo, useState } from 'react';

const GasUsageChart = React.memo(({ data }: { data: number[] }) => {
  const config = useMemo(() => ({ data }), [data]);
  return <div>{JSON.stringify(config)}</div>;
});

export default function Home() {
  const [data, setData] = useState([1, 2, 3]);
  const stableData = useMemo(() => data, [data]);
  return (
    <div>
      <button onClick={() => setData([...data, data.length])}>Update</button>
      <GasUsageChart data={stableData} />
    </div>
  );
}