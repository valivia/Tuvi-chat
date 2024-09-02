export const ssr = false

export async function load() {
    const ws = new WebSocket(`http://127.0.0.1:8000/echo/pee`);
    console.log(ws)

    ws.onopen = () => {
        console.log("connected")
        ws.send("hello")
    }

    ws.onmessage = (event) => {
        console.log(event.data)
    }
}