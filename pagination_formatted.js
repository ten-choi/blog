var noPage;
var currentPage;
var currentPageNo;
var postLabel;
var locationUrl = location.href;
var home_page = "/";

pageCurrentBlogger();

function startPagination(a) {
  var b = '';
  pageNumber = parseInt(numOfPages / 2);
  if (pageNumber == numOfPages - pageNumber) { numOfPages = pageNumber * 2 + 1 }
  pageStart = currentPageNo - pageNumber;
  if (pageStart < 1) pageStart = 1;
  lastPageNo = parseInt(a / postResults) + 1;
  if (lastPageNo - 1 == a / postResults) lastPageNo = lastPageNo - 1;
  pageEnd = pageStart + numOfPages - 1;
  if (pageEnd > lastPageNo) pageEnd = lastPageNo;

  b += '<span class="page-of">' + pageOf[0] + ' ' + currentPageNo + ' ' + pageOf[1] + ' ' + lastPageNo + '</span>';

  var c = parseInt(currentPageNo) - 1;
  if (currentPageNo > 1) {
    if (currentPageNo == 2) {
      if (currentPage == 'page') {
        b += '<a class="page-num page-prev" href="' + home_page + '"></a>';
      } else {
        b += '<a class="page-num page-prev" href="/search/label/' + postLabel + '?&max-results=' + postResults + '"></a>';
      }
    } else {
      if (currentPage == 'page') {
        b += '<a class="page-num page-prev" href="#" onclick="getPage(' + c + ');return false"></a>';
      } else {
        b += '<a class="page-num page-prev" href="#" onclick="getLabelPage(' + c + ');return false"></a>';
      }
    }
  }

  if (pageStart > 1) {
    if (currentPage == "page") {
      b += '<a class="page-num" href="' + home_page + '">1</a>';
    } else {
      b += '<a class="page-num" href="/search/label/' + postLabel + '?&max-results=' + postResults + '">1</a>';
    }
  }
  if (pageStart > 2) { b += '<span class="page-num page-dots">...</span>' }

  for (var d = pageStart; d <= pageEnd; d++) {
    if (currentPageNo == d) {
      b += '<span class="page-num page-active">' + d + '</span>';
    } else if (d == 1) {
      if (currentPage == 'page') {
        b += '<a class="page-num" href="' + home_page + '">1</a>';
      } else {
        b += '<a class="page-num" href="/search/label/' + postLabel + '?&max-results=' + postResults + '">1</a>';
      }
    } else {
      if (currentPage == 'page') {
        b += '<a class="page-num" href="#" onclick="getPage(' + d + ');return false">' + d + '</a>';
      } else {
        b += '<a class="page-num" href="#" onclick="getLabelPage(' + d + ');return false">' + d + '</a>';
      }
    }
  }

  if (pageEnd < lastPageNo - 1) { b += '<span class="page-num page-dots">...</span>' }
  if (pageEnd < lastPageNo) {
    if (currentPage == "page") {
      b += '<a class="page-num" href="#" onclick="getPage(' + lastPageNo + ');return false">' + lastPageNo + '</a>';
    } else {
      b += '<a class="page-num" href="#" onclick="getLabelPage(' + lastPageNo + ');return false">' + lastPageNo + '</a>';
    }
  }

  var e = parseInt(currentPageNo) + 1;
  if (currentPageNo < lastPageNo) {
    if (currentPage == 'page') {
      b += '<a class="page-num page-next" href="#" onclick="getPage(' + e + ');return false"></a>';
    } else {
      b += '<a class="page-num page-next" href="#" onclick="getLabelPage(' + e + ');return false"></a>';
    }
  }

  var f = document.getElementsByName('pageArea');
  var g = document.getElementById('blog-pager');
  for (var p = 0; p < f.length; p++) { f[p].innerHTML = b }
  if (f && f.length > 0) { b = '' }
  if (g) { g.innerHTML = b }
}

function dataFeed(a) {
  var b = a.feed;
  var c = parseInt(b.openSearch$totalResults.$t, 10);
  startPagination(c);
}

function pageCurrentBlogger() {
  var a = locationUrl;
  if (a.indexOf('/search/label/') != -1) {
    if (a.indexOf('?updated-max') != -1) {
      postLabel = a.substring(a.indexOf('/search/label/') + 14, a.indexOf('?updated-max'));
    } else {
      postLabel = a.substring(a.indexOf('/search/label/') + 14, a.indexOf('?&max'));
    }
  }
  if (a.indexOf('?q=') == -1 && a.indexOf('.html') == -1) {
    if (a.indexOf('/search/label/') == -1) {
      currentPage = 'page';
      if (locationUrl.indexOf('#PageNo=') != -1) {
        currentPageNo = locationUrl.substring(locationUrl.indexOf('#PageNo=') + 8, locationUrl.length);
      } else {
        currentPageNo = 1;
      }
      document.write('<script src=\'' + home_page + 'feeds/posts/summary?max-results=1&alt=json-in-script&callback=dataFeed\'><\/script>');
    } else {
      currentPage = 'label';
      if (a.indexOf('&max-results=') == -1) { postResults = 20 }
      if (locationUrl.indexOf('#PageNo=') != -1) {
        currentPageNo = locationUrl.substring(locationUrl.indexOf('#PageNo=') + 8, locationUrl.length);
      } else {
        currentPageNo = 1;
      }
      document.write('<script src="' + home_page + 'feeds/posts/summary/-/' + postLabel + '?alt=json-in-script&callback=dataFeed&max-results=1" ><\/script>');
    }
  }
}

function getPage(a) {
  jsonstart = (a - 1) * postResults;
  noPage = a;
  var b = document.getElementsByTagName('head')[0];
  var c = document.createElement('script');
  c.type = 'text/javascript';
  c.setAttribute('src', home_page + 'feeds/posts/summary?start-index=' + jsonstart + '&max-results=1&alt=json-in-script&callback=findPostDate');
  b.appendChild(c);
}

function getLabelPage(a) {
  jsonstart = (a - 1) * postResults;
  noPage = a;
  var b = document.getElementsByTagName('head')[0];
  var c = document.createElement('script');
  c.type = 'text/javascript';
  c.setAttribute('src', home_page + 'feeds/posts/summary/-/' + postLabel + '?start-index=' + jsonstart + '&max-results=1&alt=json-in-script&callback=findPostDate');
  b.appendChild(c);
}

function findPostDate(a) {
  post = a.feed.entry[0];
  var b = post.published.$t.substring(0, 19) + post.published.$t.substring(23, 29);
  var c = encodeURIComponent(b);
  if (currentPage == 'page') {
    var d = '/search?updated-max=' + c + '&max-results=' + postResults + '#PageNo=' + noPage;
  } else {
    var d = '/search/label/' + postLabel + '?updated-max=' + c + '&max-results=' + postResults + '#PageNo=' + noPage;
  }
  location.href = d;
}
