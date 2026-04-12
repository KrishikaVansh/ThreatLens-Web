import axios from "axios";

const api = axios.create({ baseURL: "/api" });

export const checkURL   = (url)   => api.post("/check", { url });
export const checkBulk  = (urls)  => api.post("/bulk",  { urls });
export const getHistory = (params) => api.get("/history", { params });
export const getStats   = ()      => api.get("/stats");
export const deleteScan = (id)    => api.delete(`/history/${id}`);
