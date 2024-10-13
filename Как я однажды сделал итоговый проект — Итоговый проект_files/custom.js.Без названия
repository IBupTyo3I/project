(function($) {
  'use strict';

    $( document ).ready(function() {
		
		$(window).on('scroll', function () {
		  if ($(this).scrollTop() > 200) {
			$('.scrollingUp').addClass('is-active');
		  } else {
			$('.scrollingUp').removeClass('is-active');
		  }
		});
		$(window).on('scroll', function() {
		  if ($(window).scrollTop() >= 250) {
			  $('.is-sticky-on').addClass('is-sticky-menu');
		  }
		  else {
			  $('.is-sticky-on').removeClass('is-sticky-menu');
		  }
		});
		
		$(window).bind("scroll", function(){if ($(".scrollingUp").length){
			let b = $("body").height(),c = $(window).height(),d = b - c,e = $(window).scrollTop(),f = 250 - e / d * 150;
			$(".scrollingUp circle").css("stroke-dashoffset", f + "px")
		}}),$('.scrollingUp').click(function(b){return b.preventDefault(),$('html, body').animate({scrollTop:0},320),!1});

        // Sticky Header
        $(window).on('scroll', function() {
          if ($(window).scrollTop() >= 250) {
              $('.is-sticky-on').addClass('is-sticky-menu');
          }
          else {
              $('.is-sticky-on').removeClass('is-sticky-menu');
          }
        });
    });
	
  // Home Slider
    var $owlHome = $('.home-slider');
    $owlHome.owlCarousel({
      rtl: $("html").attr("dir") == 'rtl' ? true : false,
      items: 1,
      autoplay: true,
      autoplayTimeout: 10000,
      margin: 0,
      loop: true,
      dots: false,
      nav: true,
      navText: ['<i class="fa fa-angle-left"></i>', '<i class="fa fa-angle-right"></i>'],
      singleItem: true,
      transitionStyle: "fade",
      touchDrag: true,
      mouseDrag: true,
      responsive: {
        0: {
          nav: false
        },
        768: {
          nav: true
        },
        992: {
          nav: true
        }
      }
    });
    $owlHome.owlCarousel();
    $owlHome.on('translate.owl.carousel', function (event) {
        var data_anim = $("[data-animation]");
        data_anim.each(function() {
            var anim_name = $(this).data('animation');
            $(this).removeClass('animated ' + anim_name).css('opacity', '0');
        });
    });
    $("[data-delay]").each(function() {
        var anim_del = $(this).data('delay');
        $(this).css('animation-delay', anim_del);
    });
    $("[data-duration]").each(function() {
        var anim_dur = $(this).data('duration');
        $(this).css('animation-duration', anim_dur);
    });
    $owlHome.on('translated.owl.carousel', function() {
        var data_anim = $owlHome.find('.owl-item.active').find("[data-animation]");
        data_anim.each(function() {
            var anim_name = $(this).data('animation');
            $(this).addClass('animated ' + anim_name).css('opacity', '1');
        });
    });
  
}(jQuery));


! function(e, t) {
    "use strict";
    ({
        customID: "flixitaCoreScript", $document: e(document), $window: e(window), $body: e("body"),
        classes: {overlayActive: "overlay-enabled",collapsed: "collapsed",mainHeaderMenuActive: "header-menu-active",searchPopUpActive: "header-search-active"},
        init: function() {
            this.$document.on("ready", this.flixitaIsDocumentReady.bind(this)),
			this.$document.on("ready", this.flixitaMobileMenuClone.bind(this)),
			this.$window.on("ready", this.flixitaIsDocumentReady.bind(this))
        },
        flixitaIsDocumentReady: function() {
            this.$document
			.on("click." + this.customID, ".menu-collapsed", this.flixitaMenuCollapse.bind(this))
			.on("click." + this.customID, ".header-close-menu", this.flixitaMenuCollapse.bind(this))
			.on("click." + this.customID, this.flixitaMenuHideMobilePopup.bind(this))
			.on("click." + this.customID, ".mobile-collapsed", this.flixitaMobileSubmenuCollapse.bind(this))
			.on("click." + this.customID, ".header-close-menu", this.flixitaResetMobileMenuCollapse.bind(this))
			.on("flixitaMenuHideMobilePopup." + this.customID, this.flixitaResetMobileMenuCollapse.bind(this))
			.on("click." + this.customID, ".header-search-toggle", this.flixitaSearchPopUpToggle.bind(this))
			.on("click." + this.customID, ".header-search-close", this.flixitaSearchPopUpToggle.bind(this)), this.$window.on("load." + this.customID, this.flixitaMenuAccessibility.bind(this))
        },
		flixitaSearchPopUpToggle: function(t) {
            var i = e(".header-search-toggle"),
                n = e(".header-search-field");
            this.$body.toggleClass(this.classes.searchPopUpActive), this.$body.hasClass(this.classes.searchPopUpActive) ? n.focus() : i.focus(), this.flixitaSearchPopupAccessibility()
        },
		flixitaSearchPopupAccessibility: function() {
            var e, t, i, n = document.querySelector(".header-search-popup");
            let a = document.querySelector(".header-search-field"),
                s = n.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
                o = s[s.length - 1];
            if (!n) return !1;
            for (t = 0, i = (e = n.getElementsByTagName("button")).length; t < i; t++) e[t].addEventListener("focus", c, !0), e[t].addEventListener("blur", c, !0);

            function c() {
                for (var e = this; - 1 === e.className.indexOf("header-search-popup");) "input" === e.tagName.toLowerCase() && (-1 !== e.className.indexOf("focus") ? e.className = e.className.replace("focus", "") : e.className += " focus"), e = e.parentElement
            }
            document.addEventListener("keydown", function(e) {
                ("Tab" === e.key || 9 === e.keyCode) && (e.shiftKey ? document.activeElement === a && (o.focus(), e.preventDefault()) : document.activeElement === o && (a.focus(), e.preventDefault()))
            })
        },
        flixitaMobileMenuClone: function(t) {
            e(".main-navbar:not(.breadcrumb-menu) .main-menu").clone().appendTo(".main-mobile-build")
        },
        flixitaMenuAccessibility: function(t) {
            e(".main-navbar, .widget_nav_menu").find("a").on("focus blur", function() {
                e(this).parents("ul, li").toggleClass("focus")
            })
        },
        flixitaMenuCollapse: function(t) {
            var i = e(".menu-collapsed");
            this.$body.toggleClass(this.classes.mainHeaderMenuActive), this.$body.toggleClass(this.classes.overlayActive), i.toggleClass(this.classes.collapsed), this.$body.hasClass(this.classes.mainHeaderMenuActive) ? e(".header-close-menu").focus() : i.focus(), this.flixitaMainMenuAccessibility()
        },
        flixitaMainMenuAccessibility: function() {
            var e, t, i, n = document.querySelector(".main-mobile-build");
            let a = document.querySelector(".header-close-menu"),
                s = n.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
                o = s[s.length - 1];
            if (!n) return !1;
            for (t = 0, i = (e = n.getElementsByTagName("a")).length; t < i; t++) e[t].addEventListener("focus", c, !0), e[t].addEventListener("blur", c, !0);

            function c() {
                for (var e = this; - 1 === e.className.indexOf("main-mobile-build");) "li" === e.tagName.toLowerCase() && (-1 !== e.className.indexOf("focus") ? e.className = e.className.replace(" focus", "") : e.className += " focus"), e = e.parentElement
            }
            document.addEventListener("keydown", function(e) {
                ("Tab" === e.key || 9 === e.keyCode) && (e.shiftKey ? document.activeElement === a && (o.focus(), e.preventDefault()) : document.activeElement === o && (a.focus(), e.preventDefault()))
            })
        },
        flixitaMenuHideMobilePopup: function(t) {
            var i = e(".menu-collapsed"),
                n = e(".main-mobile-build");
            e(t.target).closest(i).length || e(t.target).closest(n).length || this.$body.hasClass(this.classes.mainHeaderMenuActive) && (this.$body.removeClass(this.classes.mainHeaderMenuActive), this.$body.removeClass(this.classes.overlayActive), i.removeClass(this.classes.collapsed), this.$document.trigger("flixitaMenuHideMobilePopup." + this.customID), t.stopPropagation())
        },
        flixitaMobileSubmenuCollapse: function(t) {
            t.preventDefault();
            var i = e(t.currentTarget);
            i.closest(".main-mobile-build .main-menu"), i.parents(".dropdown-menu").length;
            this.isRTL, setTimeout(function() {
                i.parent().toggleClass("current"), i.next().slideToggle()
            }, 250)
        },
        flixitaResetMobileMenuCollapse: function(t) {
            e(".main-mobile-build .main-menu");
            var i = e(".main-mobile-build  .menu-item"),
                n = e(".main-mobile-build .dropdown-menu");
            setTimeout(function() {
                i.removeClass("current"), n.hide()
            }, 250)
        }
    }).init()
}(jQuery, window.flixitaCoreScript);