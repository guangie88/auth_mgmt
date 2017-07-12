
const app = new Vue({
  // router,
  el: '#app',

  data: {
    adminTaskCreds: null,
    selectedExchange: null,
    selectedUpdate: { username: null, password: null },
    toAddCreds: null,
    toDeleteUsers: null,
    toUpdateUsers: null,
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

    deleteUsers() {
      const confirmDeleteUserGroups = _.filter(this.toDeleteUsers, toDeleteUser => toDeleteUser.delete);
      const confirmDeleteUsernames = _.map(confirmDeleteUserGroups, confirmDeleteUserGroup => confirmDeleteUserGroup.username);

      // DELETE has a different API from POST
      axios.delete('/force_delete_mappings', { data: confirmDeleteUsernames, headers: { 'Content-Type': 'application/json' } })
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.reload();
          } else {
            alert(resp.data.status);
          }
        })
        .catch(error => alert(JSON.stringify(error)));
    },

    exchange() {
      axios.post('/exchange', this.selectedUpdate)
        .then(resp => {
          if (resp.data.status == 'ok') {
            this.selectedExchange = resp.data.data;
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

    updateUser() {

    },
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
          this.users = _.sortBy(resp.data.data, user => user);

          this.toDeleteUsers = _.map(this.users, user => {
            return { username: user, delete: false };
          });

          this.toUpdateUsers = _.map(this.users, user => {
            return { username: user, selected: false };
          });
        }
      })
      .catch(error => alert(JSON.stringify(error)));
  },
});