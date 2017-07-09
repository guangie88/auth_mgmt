const router = new VueRouter({
  mode: 'history',
  routes: [],
});

const Main = new Vue({
  router,
  el: '#app',

  data: {
    adminTaskCreds: '[not ready]',

    logout() {
      this.$cookies.remove('token', '/', window.location.hostname);
      router.push('/');
      router.go();
    },

    // tableData: [{
    //   date: '2016-05-03',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-02',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-04',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-01',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }]
  },

  mounted() {
    axios.get('/info')
      .then(resp => {
        if (resp.data.status == "ok") {
          this.adminTaskCreds = resp.data.data;
        } else {
          this.adminTaskCreds = resp.data.status;
        }
      })
      .catch(error => alert(JSON.stringify(error)));
  },
});