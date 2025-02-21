export default {
  async fetch(request) {
    let url = new URL(request.url);
    url.hostname = "byeonggon7.github.io"; // Point to GitHub Pages
    url.pathname = "/Project1" + url.pathname; // Ensure correct path

    try {
      let response = await fetch(url.toString(), request);
      let newHeaders = new Headers(response.headers);

      // Cache static files (CSS, JS, Images)
      if (url.pathname.match(/\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico)$/)) {
          newHeaders.set("Cache-Control", "public, max-age=31536000, immutable");
      } else {
          newHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
      }

      return new Response(response.body, {
        status: response.status,
        headers: newHeaders,
      });

    } catch (error) {
      return new Response("Error: " + error.message, { status: 500 });
    }
  },
};
