// The install guides moved into Get started: old #pi, #native, #k8s, #router, ... links still land (install.html).
(function () {
  var map = { hybrid: "cluster" };
  var h = location.hash.slice(1);
  location.replace("start.html" + (h ? "#" + (map[h] || h) : "#install"));
})();
