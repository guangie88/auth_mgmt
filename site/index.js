const router = new VueRouter({
  mode: 'history',
  routes: [],
});

const Main = new Vue({
  router,
  el: '#app',

  data: {
    hasFailedLogin: false,
  },

  mounted() {
    this.hasFailedLogin = this.$route.query.failed;
  },
});