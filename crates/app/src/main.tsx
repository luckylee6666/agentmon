import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

// A WKWebView lets a trackpad pinch magnify the whole UI, which silently
// scales every panel and clips the layout. The pinch arrives as a wheel event
// with ctrlKey set, and the keyboard equivalents are worth blocking too.
// Only zoom-in is blocked: zoom-out stays available so a magnified window can
// always be recovered without restarting the app.
document.addEventListener(
  "wheel",
  (event) => {
    if (event.ctrlKey && event.deltaY < 0) event.preventDefault();
  },
  { passive: false },
);
document.addEventListener("keydown", (event) => {
  if (!(event.metaKey || event.ctrlKey)) return;
  if (["+", "="].includes(event.key)) event.preventDefault();
});


ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
