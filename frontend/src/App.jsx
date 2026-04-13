import { Routes, Route } from "react-router-dom";
import Navbar    from "./components/Navbar";
import Home      from "./pages/Home";
import Scan      from "./pages/Scan";
import Bulk      from "./pages/Bulk";
import History   from "./pages/History";
import Dashboard from "./pages/Dashboard";
import About     from "./pages/About";
import styles    from "./App.module.css";

export default function App() {
  return (
    <div className={styles.app}>
      <Navbar />
      <main>
        <Routes>
          <Route path="/"          element={<Home />} />
          <Route path="/scan"      element={<Scan />} />
          <Route path="/bulk"      element={<Bulk />} />
          <Route path="/history"   element={<History />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/about"     element={<About />} />
        </Routes>
      </main>
    </div>
  );
}
