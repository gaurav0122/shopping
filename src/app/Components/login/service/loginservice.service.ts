import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot, UrlTree } from '@angular/router';
import { map, Observable } from 'rxjs';
import { User } from '../Model/user.model';

@Injectable({
  providedIn: 'root'
})
export class LoginserviceService{

  USER_NAME_SESSION_ATTRIBUTE_NAME = 'authenticatedUser'

  public username: string;
  public password: string;

  getUserApi:string;
  //getAllUserApi:string;

  constructor(private http:HttpClient,private router:Router) {
      this.getUserApi="http://localhost:8111/profile-service/user/user/email/";
   //   this.getAllUserApi="http://localhost:8095/user/user";
      this.username="";
      this.password="";
   }



   authenticationService(username: string, password: string){
    return this.http.get(this.getUserApi+username,
      { headers: { authorization: this.createBasicAuthToken(username, password) } }).pipe(map((res) => {
        this.username = username;
        this.password = password;
        this.registerSuccessfulLogin(username, password);
      }));
  }

  createBasicAuthToken(username: string, password: string) {
    return 'Basic ' + window.btoa(username + ":" + password)
  }

  registerSuccessfulLogin(username:string, password:string) {
    localStorage.setItem("auth",this.createBasicAuthToken(username,password))
    sessionStorage.setItem(this.USER_NAME_SESSION_ATTRIBUTE_NAME,username);
  }

  isUserLoggedIn() {
    let user = sessionStorage.getItem(this.USER_NAME_SESSION_ATTRIBUTE_NAME)
    if (user === null) return false
    return true
  }

  getLoggedInUserName() {
    let user = sessionStorage.getItem(this.USER_NAME_SESSION_ATTRIBUTE_NAME)
    if (user === null) return ''
    return user
  }

  getUserByEmail(email:string):Observable<User>{
    let token1:string=localStorage.getItem("auth")!;
    console.log(token1);
    return this.http.get<User>(this.getUserApi+email, { headers: { authorization:token1} });
   }

}
