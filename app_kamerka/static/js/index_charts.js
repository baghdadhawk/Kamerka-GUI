/* Shared restrained categorical palette for every dashboard chart (Morris
   bar/donut, the vulnerabilities wordcloud), derived from the theme's CSS
   custom properties (kamerka-modern.css :root) so it tracks the active
   theme (dark/light, see the theme toggle in _nav.html) instead of a
   separate hardcoded color list. Falls back to sane literals if the
   variables are ever missing (e.g. this script runs before the stylesheet
   parses). */
function kamChartPalette(){
    var css = (document.documentElement && window.getComputedStyle) ?
        window.getComputedStyle(document.documentElement) : null;
    function v(name, fallback){
        var val = css ? css.getPropertyValue(name) : '';
        val = val ? val.trim() : '';
        return val || fallback;
    }
    return [
        v('--km-chart-1', '#00e1ff'),
        v('--km-chart-2', '#22c58b'),
        v('--km-chart-3', '#ffb020'),
        v('--km-chart-4', '#7c93ff'),
        v('--km-chart-5', '#00b8d1'),
        v('--km-chart-6', '#4fe0b3')
    ];
}

/* Map/grid colors (dashboard jvectormap + Morris grid line), also derived
   from kamerka-modern.css :root tokens so they track the active theme.
   Kept separate from kamChartPalette() since the map has its own token
   names (--km-map-*) and its own re-render path -- see
   kamRenderDashboardMap()/kamRedrawDashboardMap() below. */
function kamMapColors(){
    var css = (document.documentElement && window.getComputedStyle) ?
        window.getComputedStyle(document.documentElement) : null;
    function v(name, fallback){
        var val = css ? css.getPropertyValue(name) : '';
        val = val ? val.trim() : '';
        return val || fallback;
    }
    return {
        background: v('--km-map-bg', '#0a141d'),
        region: v('--km-map-region', '#33414e'),
        selected: v('--km-map-selected', '#ff2fd1'),
        scaleFrom: v('--km-map-scale-from', '#1a212c'),
        scaleTo: v('--km-map-scale-to', '#00e1ff'),
        marker: v('--km-map-marker', '#22c58b'),
        gridLine: v('--km-morris-grid', '#00b8d1')
    };
}

/* Renders (or re-renders) the dashboard world map with the current theme's
   colors. Safe to call more than once on the same page: jvectormap has no
   CSS hook of its own (colors are baked in at construction), so a theme
   toggle has to tear the previous map down (jvm's own .remove(), which
   detaches its internal container) and build a fresh one rather than
   restyle in place. window.kamDashboardCountries holds the last data set
   passed in so a later re-theme (see _nav.html's toggle handler) can
   re-render without needing the page to re-fetch anything. */
function kamRenderDashboardMap(countries){
    if ($('#dashboard-map-seles').length === 0) { return; }
    if (window.kamDashboardMap && typeof window.kamDashboardMap.remove === 'function') {
        try { window.kamDashboardMap.remove(); } catch (e) {}
        window.kamDashboardMap = null;
    }
    var colors = kamMapColors();
    window.kamDashboardMap = new jvm.WorldMap({container: $('#dashboard-map-seles'),
                                    map: 'world_mill_en',
                                    backgroundColor: colors.background,
                                    regionsSelectable: true,
                                    regionStyle: {selected: {fill: colors.selected},
                                                    initial: {fill: colors.region}},
                                    markerStyle: {initial: {fill: colors.marker,
                                                   stroke: colors.marker}},
                                    onRegionClick: function(e, code){
                                        if (code) {
                                            window.location.href = '/devices?country=' + encodeURIComponent(String(code).toUpperCase());
                                        }
                                    },
                                    series: {
                                        regions: [
                                            {
                                            scale: [colors.scaleFrom, colors.scaleTo],
                                            attribute: 'fill',
                                            normalizeFunction: 'polynomial',
                                            values: countries}]
        },
                                });
}

/* Called by _nav.html's theme toggle so the map recolors immediately
   instead of waiting for a full page reload. Only the map is re-rendered
   here (not the Morris bar/donut, which would duplicate SVGs if re-created
   on top of themselves) -- see the STAGE 3 map-theming notes. */
window.kamRedrawDashboardMap = function(){
    if (window.kamDashboardCountries !== undefined) {
        kamRenderDashboardMap(window.kamDashboardCountries);
    }
};

function drawcharts(ics_len,coordinates_search_len, healthcare_len, ports, countries){
//console.log(ports)
    /* reportrange */
    if($("#reportrange").length > 0){
        $("#reportrange").daterangepicker({
            ranges: {
               'Today': [moment(), moment()],
               'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
               'Last 7 Days': [moment().subtract(6, 'days'), moment()],
               'Last 30 Days': [moment().subtract(29, 'days'), moment()],
               'This Month': [moment().startOf('month'), moment().endOf('month')],
               'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
            },
            opens: 'left',
            buttonClasses: ['btn btn-default'],
            applyClass: 'btn-small btn-primary',
            cancelClass: 'btn-small',
            format: 'MM.DD.YYYY',
            separator: ' to ',
            startDate: moment().subtract('days', 29),
            endDate: moment()
          },function(start, end) {
              $('#reportrange span').html(start.format('MMMM D, YYYY') + ' - ' + end.format('MMMM D, YYYY'));
        });

        $("#reportrange span").html(moment().subtract('days', 29).format('MMMM D, YYYY') + ' - ' + moment().format('MMMM D, YYYY'));
    }

    /* Category (ICS/Coordinates/Healthcare) -> devices?category=<x> */
    var dashboardCategoryToParam = {
        "ICS": "ics",
        "Coordinates": "coordinates",
        "Healthcare": "healthcare"
    };

    /* Donut dashboard chart -- one restrained categorical palette (cyan
       primary + harmonious hues) shared with the bar chart and wordcloud,
       see kamChartPalette() above, plus an HTML legend since Morris has no
       built-in one. */
    var kamPalette = kamChartPalette();
    var kamColors = kamMapColors();
    if ($('#dashboard-donut-1').length > 0) {
        var donutData = [
            {label: "ICS", value: ics_len},
            {label: "Coordinates", value: coordinates_search_len},
            {label: "Healthcare", value: healthcare_len},
        ];
        var dashboardDonut = Morris.Donut({
            labelColor: kamPalette[0],
            element: 'dashboard-donut-1',
            data: donutData,
            colors: kamPalette,
            resize: true
        });
        dashboardDonut.on('click', function(i, row){
            var category = dashboardCategoryToParam[row.label];
            if (category) {
                window.location.href = '/devices?category=' + encodeURIComponent(category);
            }
        });

        var $legend = $('#dashboard-donut-1-legend');
        if ($legend.length > 0) {
            $.each(donutData, function(i, row){
                if (!row.value) { return; }
                var swatch = $('<span class="km-legend-swatch"></span>').css('background-color', kamPalette[i % kamPalette.length]);
                var $item = $('<span class="km-legend-item"></span>').append(swatch).append(' ' + row.label + ' (' + row.value + ')');
                $legend.append($item);
            });
        }
    }
    /* END Donut dashboard chart */
    /* Bar dashboard chart */
    if ($('#dashboard-bar-1').length > 0) {
        var dashboardBar = Morris.Bar({
            element: 'dashboard-bar-1',
            data: ports,
            xkey: 'port',
            ykeys: [ 'c'],
            labels: ['Total results'],
            barColors: kamPalette,
            gridTextSize: '10px',
            gridTextColor: kamPalette[0],
            xLabelMargin: 10,
            xLabelAngle: 60,
            hideHover: true,
            resize: true,
            gridLineColor: kamColors.gridLine
        });
        dashboardBar.on('click', function(i, row){
            if (row && row.port) {
                window.location.href = '/devices?port=' + encodeURIComponent(row.port);
            }
        });
    }
    /* END Bar dashboard chart */
    
//    /* Line dashboard chart */
//    Morris.Line({
//      element: 'dashboard-line-1',
//      data: [
//        { y: '2014-10-10', a: 2,b: 4},
//        { y: '2014-10-11', a: 4,b: 6},
//        { y: '2014-10-12', a: 7,b: 10},
//        { y: '2014-10-13', a: 5,b: 7},
//        { y: '2014-10-14', a: 6,b: 9},
//        { y: '2014-10-15', a: 9,b: 12},
//        { y: '2014-10-16', a: 18,b: 20}
//      ],
//      xkey: 'y',
//      ykeys: ['a','b'],
//      labels: ['Sales','Event'],
//      resize: true,
//      hideHover: true,
//      xLabels: 'day',
//      gridTextSize: '10px',
//      lineColors: ['#1caf9a','#33414E'],
//      gridLineColor: '#E5E5E5'
//    });
    /* EMD Line dashboard chart */
    /* Moris Area Chart */
//      Morris.Area({
//      element: 'dashboard-area-1',
//      data: [
//        { y: '2014-10-10', a: 17,b: 19},
//        { y: '2014-10-11', a: 19,b: 21},
//        { y: '2014-10-12', a: 22,b: 25},
//        { y: '2014-10-13', a: 20,b: 22},
//        { y: '2014-10-14', a: 21,b: 24},
//        { y: '2014-10-15', a: 34,b: 37},
//        { y: '2014-10-16', a: 43,b: 45}
//      ],
//      xkey: 'y',
//      ykeys: ['a','b'],
//      labels: ['Sales','Event'],
//      resize: true,
//      hideHover: true,
//      xLabels: 'day',
//      gridTextSize: '10px',
//      lineColors: ['#1caf9a','#33414E'],
//      gridLineColor: '#E5E5E5'
//    });
//    /* End Moris Area Chart */
    /* Vector Map -- colors + rendering live in kamRenderDashboardMap()
       above so the same code path handles both the initial paint and a
       theme-toggle re-render (window.kamRedrawDashboardMap). */
    window.kamDashboardCountries = countries;
    kamRenderDashboardMap(countries);
    /* END Vector Map */

    
    $(".x-navigation-minimize").on("click",function(){
        setTimeout(function(){
            rdc_resize();
        },200);    
    });
    
    
};

