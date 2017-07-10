
const app = new Vue({
  // router,
  el: '#app',

  data: {
    adminTaskCreds: null,
    toAddCreds: null,
    users: [],
    
    addUser() {
      axios.post('/add_mapping', this.toAddCreds)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.reload();
          } else {
            alert(resp.data.status);
          }
        })
        .catch(error => alert(JSON.stringify(error)));
    },

    logout() {
      this.$cookies.remove('token', '/', window.location.hostname);
      window.location.href = '/';
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
        if (resp.data.status == 'ok') {
          this.adminTaskCreds = resp.data.data;
        }
      })
      .catch(error => alert(JSON.stringify(error)));

    axios.get('/get_default_creds')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.toAddCreds = resp.data.data;
        }
      })

    axios.get('/get_users')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.users = resp.data.data;
        }
      })
      .catch(error => alert(JSON.stringify(error)));
  },
});