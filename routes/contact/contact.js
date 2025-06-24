import 'dotenv/config'

export default async function contact(data) {
    fetch(process.env.DISCORD_WEBHOOK_URI, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-type': 'application/json; charset=UTF-8',
        },
    })
        .then((response) => response.json())
        .then((json) => console.log(json))
}
