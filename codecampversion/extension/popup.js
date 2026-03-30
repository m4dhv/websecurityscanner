document.getElementById("scanBtn").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab.url;

  document.getElementById("result").innerText = "Scanning...";

  try {
    const response = await fetch("http://127.0.0.1:5000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    document.getElementById("result").innerText =
      JSON.stringify(data, null, 2);

  } catch (error) {
    document.getElementById("result").innerText =
      "Error connecting to scanner backend";
  }
});