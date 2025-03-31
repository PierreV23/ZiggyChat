export function createWS(tag, token) {
    const socket = new WebSocket(`/ws/${tag}/${token}/`);
    return socket;
}