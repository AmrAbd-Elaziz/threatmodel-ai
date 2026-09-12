import {
  BrowserRouter,
  Route,
  Routes,
} from "react-router-dom";

import Dashboard from "./Dashboard";
import Architecture from "./Architecture";
import AttackPaths from "./AttackPaths";
import Threats from "./Threats";
import Controls from "./Controls";
import Findings from "./Findings";
import Reassessment from "./Reassessment";
import Reports from "./Reports";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={<Dashboard />}
        />

        <Route
          path="/architecture"
          element={<Architecture />}
        />

        <Route
          path="/attack-paths"
          element={<AttackPaths />}
        />

        <Route
          path="/threats"
          element={<Threats />}
        />

        <Route
          path="/controls"
          element={<Controls />}
        />

        <Route
          path="/findings"
          element={<Findings />}
        />

        <Route
          path="/reassessment"
          element={<Reassessment />}
        />

        <Route
          path="/reports"
          element={<Reports />}
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
