import { Routes, Route } from "react-router-dom";
import Navbar    from "./components/Navbar";
import Home      from "./pages/Home";
import Bulk      from "./pages/Bulk";
import History   from "./pages/History";
import Dashboard from "./pages/Dashboard";
import styles    from "./App.module.css";

export default function App() {
  return (
    <div className={styles.app}>
      <Navbar />
      <main className={styles.main}>
        <Routes>
          <Route path="/"          element={<Home />} />
          <Route path="/bulk"      element={<Bulk />} />
          <Route path="/history"   element={<History />} />
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </main>
    </div>
  );
}
