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
            gridLineColor: '#0064d7'
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
    /* Vector Map */
    var mapData = countries;
        var colorScale = ['#f0f0f0', '#C8EEFF', '#0071A4', '#FFA500', '#ff0000'];

    if ($('#dashboard-map-seles').length > 0) {
    var jvm_wm = new jvm.WorldMap({container: $('#dashboard-map-seles'),
                                    map: 'world_mill_en',
                                    backgroundColor: '#0a141d',
                                    regionsSelectable: true,
                                    regionStyle: {selected: {fill: '#ff00cd'},
                                                    initial: {fill: '#33414E'}},
                                    markerStyle: {initial: {fill: '#1caf9a',
                                                   stroke: '#1caf9a'}},
                                    onRegionClick: function(e, code){
                                        if (code) {
                                            window.location.href = '/devices?country=' + encodeURIComponent(String(code).toUpperCase());
                                        }
                                    },
//                                    markers: [{latLng: [50.27, 30.31], name: pies},
//                                              {latLng: [52.52, 13.40], name: 'Berlin - 2'},
//                                              {latLng: [48.85, 2.35], name: 'Paris - 1'},
//                                              {latLng: [51.51, -0.13], name: 'London - 3'},
//                                              {latLng: [40.71, -74.00], name: 'New York - 5'},
//                                              {latLng: [35.38, 139.69], name: 'Tokyo - 12'},
//                                              {latLng: [37.78, -122.41], name: 'San Francisco - 8'},
//                                              {latLng: [28.61, 77.20], name: 'New Delhi - 4'},
//                                              {latLng: [39.91, 116.39], name: 'Beijing - 3'}],
                                    series: {
                                        regions: [
                                            {
                                            scale: ["#ff00cd"],
                                            attribute: 'fill',
                                            normalizeFunction: 'polynomial',
                                            values: mapData}]
        },
                                });
    }
    /* END Vector Map */

    
    $(".x-navigation-minimize").on("click",function(){
        setTimeout(function(){
            rdc_resize();
        },200);    
    });
    
    
};

