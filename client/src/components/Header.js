import React from "react";
//react 에서 img import 하는법 https://velog.io/@ingdol2/React-image-%EA%B2%BD%EB%A1%9C-%EC%84%A4%EC%A0%95%ED%95%98%EA%B8%B0
import imgLogo from "../img/realWave.gif";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
//dd

const Header = () => {
  const navigate = useNavigate();

  const logoutHandler = () => {
    sessionStorage.clear();
    navigate(`/`);
    window.location.reload();
  };
  return (
    <HeaderSection>
      <p
        onClick={() => {
          sessionStorage.getItem("isLogin") ? navigate(`/main`) : navigate(`/`);
        }}
        data-item="HITCH : HIKER"
      >
        HITCH : HIKER
      </p>

      {sessionStorage.getItem("isLogin") && (
        <nav>
          <ul className="menuItems">
            <li>
              <a href="/main" data-item="mainpage">
                mainpage
              </a>
            </li>
            <li>
              <a href="/mypage" data-item="mypage">
                mypage
              </a>
            </li>

            <li>
              <button onClick={logoutHandler}>Logout</button>
            </li>
          </ul>
          {/* <details className="dropdown">
            <summary role="Button"> */}
          <img
            className="Button"
            src={imgLogo}
            alt="./newWave.gif"
            width="400"
            height="140"
          />
          <a className="banner"></a>
          {/* </summary>
            <ul>
              <li>
                <a href="#">I'm a dropdown.</a>
              </li>
              <li>
                <a href="#">In Pure CSS</a>
              </li>
              <li>
                <a href="#">As in...</a>
              </li>
              <li>
                <a href="#">No JavaScript.</a>
              </li>
              <li>
                <a href="#">At All.</a>
              </li>
            </ul>
          </details> */}
        </nav>
      )}
    </HeaderSection>
  );
};

export default Header;

const HeaderSection = styled.div`
  img {
    margin-left: 2%;
  }
  display: grid;
  place-items: center;

  * {
    padding: 0;
    margin: 0;
    summary::marker {
      display: none;
      content: "";
    }
  }
  // Developed by http://grohit.com/

  .Button {
    /* margin-top: 1rem; */
    align-items: center;
    /* margin-left: 8rem; */
    list-style-type: none;
    border-radius: 10px;
    display: inline-block;
    display: flex;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.9);
    position: relative;
    height: 10rem;
    width: 31rem;
    opacity: 100%;
  }

  #logout-btn {
    li {
      margin: 50%;
      padding: 1rem;

      a {
        text-decoration: none;
        color: #efd5c8;
        font-size: 3rem;
        font-weight: 400;
        transition: all 0.5s ease-in-out;
        position: relative;
        text-transform: uppercase;

        &::before {
          content: attr(data-item);
          transition: 0.5s;
          color: #efd5c8;
          position: absolute;
          top: 0;
          bottom: 0;
          left: 0;
          right: 0;
          width: 0;
          overflow: hidden;
        }

        &:hover {
          &::before {
            width: 100%;
            transition: all 0.5s ease-in-out;
          }
        }
      }
    }
  }
  body {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    position: relative;
    min-height: 50vh;
    font-family: Hack, monospace;
  }
  button {
    font-size: 1rem;
    background-color: #dabbc9;
    width: fit-content;
    border: 1px solid #dabbc9;
    padding: 0.1rem 1rem;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.6);
    color: #425049;
    &:hover {
      background-color: #efd5c8;
      border-color: #efd5c8;
    }
  }
  div {
    color: #727272;
    text-align: center;
  }

  p {
    line-height: 4rem;
    margin-top: 2rem;
    margin-bottom: 2rem;
    font-size: 4rem;
    color: #dabbc9;
    text-transform: uppercase;
    font-weight: 600;
    transition: all 1s ease-in-out;
    position: relative;

    &::before {
      content: attr(data-item);
      transition: all 1s ease-in-out;
      color: #efd5c8;
      position: absolute;
      top: 0;
      bottom: 0;
      left: 0;
      right: 0;
      width: 0;
      overflow: hidden;
    }

    &:hover {
      &::before {
        width: 100%;
      }
    }
  }

  nav {
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(1, 0, 0, 0.6);
    /* margin: 70px; */
    background: #d0e8f0;
    opacity: 90%;
    width: 33rem;
    padding: 0.5rem;

    .menuItems {
      list-style: none;
      display: flex;
      /* margin-left: 2rem; */
      ul {
        text-align: center;
      }
      li {
        margin: 0.5rem;

        display: inline-block;
        a {
          text-decoration: none;
          color: #8f8f8f;
          font-size: 24px;
          font-weight: 400;
          transition: all 0.5s ease-in-out;
          position: relative;
          text-transform: uppercase;

          &::before {
            content: attr(data-item);
            transition: 0.5s;
            color: #425049;
            position: absolute;
            top: 0;
            bottom: 0;
            left: 0;
            right: 0;
            width: 0;
            overflow: hidden;
          }

          &:hover {
            &::before {
              width: 100%;
              transition: all 0.5s ease-in-out;
            }
          }
        }
      }
    }
  }
`;
