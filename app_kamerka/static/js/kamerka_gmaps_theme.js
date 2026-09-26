/* Shared Google Maps dark/light style arrays + helpers, used by
   device.html, map.html and results.html so the embedded Google Map
   follows the same light/dark theme as the rest of the app (see
   _nav.html's theme toggle and kamerka-modern.css's tokens).

   Google Maps has no CSS hook for its own tiles/labels -- it only themes
   via the `styles:` array passed at construction, or later through
   map.setOptions({styles: ...}). So this file hardcodes two style sheets
   (dark / light) and:
     - kamGoogleMapStyles() picks the one matching the current
       data-theme attribute on <html>, for use at map construction time.
     - kamRegisterGoogleMap(map) remembers a created google.maps.Map
       instance so it can be restyled later.
     - kamReapplyGoogleMapTheme() re-applies the current theme's styles to
       every registered map, called by _nav.html's toggle handler.

   Guarded throughout: if the Maps JS API never loaded (missing/invalid
   key -- see each template's kamMapLoadFailed check), `google` is
   undefined and there is nothing to restyle; these helpers just no-op. */
(function () {
    var KAM_GMAP_STYLE_DARK = [
        { elementType: "geometry", stylers: [{ color: "#242f3e" }] },
        { elementType: "labels.text.stroke", stylers: [{ color: "#242f3e" }] },
        { elementType: "labels.text.fill", stylers: [{ color: "#746855" }] },
        {
          featureType: "administrative.locality",
          elementType: "labels.text.fill",
          stylers: [{ color: "#d59563" }],
        },
        {
          featureType: "poi",
          elementType: "labels.text.fill",
          stylers: [{ color: "#d59563" }],
        },
        {
          featureType: "poi.park",
          elementType: "geometry",
          stylers: [{ color: "#263c3f" }],
        },
        {
          featureType: "poi.park",
          elementType: "labels.text.fill",
          stylers: [{ color: "#6b9a76" }],
        },
        {
          featureType: "road",
          elementType: "geometry",
          stylers: [{ color: "#38414e" }],
        },
        {
          featureType: "road",
          elementType: "geometry.stroke",
          stylers: [{ color: "#212a37" }],
        },
        {
          featureType: "road",
          elementType: "labels.text.fill",
          stylers: [{ color: "#9ca5b3" }],
        },
        {
          featureType: "road.highway",
          elementType: "geometry",
          stylers: [{ color: "#746855" }],
        },
        {
          featureType: "road.highway",
          elementType: "geometry.stroke",
          stylers: [{ color: "#1f2835" }],
        },
        {
          featureType: "road.highway",
          elementType: "labels.text.fill",
          stylers: [{ color: "#f3d19c" }],
        },
        {
          featureType: "transit",
          elementType: "geometry",
          stylers: [{ color: "#2f3948" }],
        },
        {
          featureType: "transit.station",
          elementType: "labels.text.fill",
          stylers: [{ color: "#d59563" }],
        },
        {
          featureType: "water",
          elementType: "geometry",
          stylers: [{ color: "#17263c" }],
        },
        {
          featureType: "water",
          elementType: "labels.text.fill",
          stylers: [{ color: "#515c6d" }],
        },
        {
          featureType: "water",
          elementType: "labels.text.stroke",
          stylers: [{ color: "#17263c" }],
        },
    ];

    /* "Silver"-style light theme -- a common, well-known light Google Maps
       styling (soft grays, no heavy blues) that pairs with the app's light
       token palette instead of dumping the default (much bluer) Maps look
       next to the app's flatter light surfaces. */
    var KAM_GMAP_STYLE_LIGHT = [
        { elementType: "geometry", stylers: [{ color: "#f5f5f5" }] },
        { elementType: "labels.icon", stylers: [{ visibility: "off" }] },
        { elementType: "labels.text.fill", stylers: [{ color: "#616161" }] },
        { elementType: "labels.text.stroke", stylers: [{ color: "#f5f5f5" }] },
        {
          featureType: "administrative.land_parcel",
          elementType: "labels.text.fill",
          stylers: [{ color: "#bdbdbd" }],
        },
        {
          featureType: "poi",
          elementType: "geometry",
          stylers: [{ color: "#eeeeee" }],
        },
        {
          featureType: "poi",
          elementType: "labels.text.fill",
          stylers: [{ color: "#757575" }],
        },
        {
          featureType: "poi.park",
          elementType: "geometry",
          stylers: [{ color: "#e5e5e5" }],
        },
        {
          featureType: "poi.park",
          elementType: "labels.text.fill",
          stylers: [{ color: "#9e9e9e" }],
        },
        {
          featureType: "road",
          elementType: "geometry",
          stylers: [{ color: "#ffffff" }],
        },
        {
          featureType: "road.arterial",
          elementType: "labels.text.fill",
          stylers: [{ color: "#757575" }],
        },
        {
          featureType: "road.highway",
          elementType: "geometry",
          stylers: [{ color: "#dadada" }],
        },
        {
          featureType: "road.highway",
          elementType: "labels.text.fill",
          stylers: [{ color: "#616161" }],
        },
        {
          featureType: "road.local",
          elementType: "labels.text.fill",
          stylers: [{ color: "#9e9e9e" }],
        },
        {
          featureType: "transit.line",
          elementType: "geometry",
          stylers: [{ color: "#e5e5e5" }],
        },
        {
          featureType: "transit.station",
          elementType: "geometry",
          stylers: [{ color: "#eeeeee" }],
        },
        {
          featureType: "water",
          elementType: "geometry",
          stylers: [{ color: "#c9c9c9" }],
        },
        {
          featureType: "water",
          elementType: "labels.text.fill",
          stylers: [{ color: "#9e9e9e" }],
        },
    ];

    window.kamGoogleMapStyles = function () {
        var theme = (document.documentElement &&
            document.documentElement.getAttribute('data-theme')) === 'light' ? 'light' : 'dark';
        return theme === 'light' ? KAM_GMAP_STYLE_LIGHT : KAM_GMAP_STYLE_DARK;
    };

    window.kamGoogleMapInstances = window.kamGoogleMapInstances || [];

    window.kamRegisterGoogleMap = function (map) {
        if (map) { window.kamGoogleMapInstances.push(map); }
    };

    window.kamReapplyGoogleMapTheme = function () {
        if (typeof google === 'undefined' || !google.maps) { return; }
        var styles = window.kamGoogleMapStyles();
        (window.kamGoogleMapInstances || []).forEach(function (map) {
            try { map.setOptions({ styles: styles }); } catch (e) {}
        });
    };
})();
